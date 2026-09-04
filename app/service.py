from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import re

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from .config import Settings
from .models import Activation, License, LicenseDevice, LicenseStatus, SystemSetting
from .security import generate_refresh_token, sign_payload, token_fingerprint


SERIAL_RE = re.compile(r"^[A-Za-z0-9._:-]{1,160}$")


class LicenseServiceError(RuntimeError):
    def __init__(self, code: str, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def iso(value: datetime) -> str:
    return as_utc(value).isoformat().replace("+00:00", "Z")


def device_status(device: LicenseDevice, now: datetime | None = None) -> str:
    """Return the entitlement status without persisting redundant state."""
    current = as_utc(now or utcnow())
    starts_at = as_utc(device.starts_at)
    expires_at = as_utc(device.expires_at)
    if starts_at is None or expires_at is None:
        return "pending"
    return "active" if expires_at > current else "expired"


def sync_license_status(license_obj: License, now: datetime | None = None) -> str:
    """Synchronize the derived license lifecycle while preserving an explicit lock."""
    if license_obj.status == LicenseStatus.LOCKED.value:
        return license_obj.status
    current = as_utc(now or utcnow())
    if license_obj.activated_at is None:
        license_obj.status = LicenseStatus.READY.value
    elif any(device_status(item, current) == "active" for item in license_obj.devices):
        license_obj.status = LicenseStatus.ACTIVE.value
    else:
        license_obj.status = LicenseStatus.EXPIRED.value
    return license_obj.status


def normalize_serials(values: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for raw in values:
        value = str(raw).strip()
        if not value or value in seen:
            continue
        if not SERIAL_RE.fullmatch(value):
            raise LicenseServiceError("invalid_serial", f"Hardware serial không hợp lệ: {value!r}")
        seen.add(value)
        result.append(value)
    return result


def version_tuple(value: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", value or "")
    return tuple(int(item) for item in parts[:4]) or (0,)


def version_too_old(current: str, minimum: str) -> bool:
    current_parts, minimum_parts = version_tuple(current), version_tuple(minimum)
    width = max(len(current_parts), len(minimum_parts))
    return current_parts + (0,) * (width - len(current_parts)) < minimum_parts + (0,) * (width - len(minimum_parts))


class LicenseService:
    def __init__(self, settings: Settings, signing_key: Ed25519PrivateKey) -> None:
        self.settings = settings
        self.signing_key = signing_key

    def _minimum_version(self, db: Session) -> str:
        row = db.get(SystemSetting, "min_client_version")
        return row.value.strip() if row and row.value.strip() else self.settings.min_client_version

    def _license_by_key(self, db: Session, key: str) -> License:
        digest = token_fingerprint(key, self.settings.license_key_pepper)
        stmt = (
            select(License)
            .where(License.key_fingerprint == digest)
            .options(selectinload(License.customer), selectinload(License.devices), selectinload(License.activations))
            .with_for_update()
        )
        license_obj = db.scalar(stmt)
        if license_obj is None:
            raise LicenseServiceError("invalid_key", "License key không hợp lệ", 401)
        return license_obj

    def _activation_by_token(self, db: Session, refresh_token: str, installation_id: str) -> Activation:
        digest = token_fingerprint(refresh_token, self.settings.license_key_pepper)
        stmt = (
            select(Activation)
            .where(Activation.refresh_token_hash == digest, Activation.installation_id == installation_id)
            .options(selectinload(Activation.license).selectinload(License.customer), selectinload(Activation.license).selectinload(License.devices))
            .with_for_update()
        )
        activation = db.scalar(stmt)
        if activation is None or activation.revoked_at is not None:
            raise LicenseServiceError("invalid_token", "Phiên kích hoạt không hợp lệ hoặc đã bị thu hồi", 401)
        return activation

    def _validate_license(self, license_obj: License, now: datetime) -> None:
        if not license_obj.customer.is_active:
            raise LicenseServiceError("locked", "Khách hàng đã bị admin khóa", 403)
        if license_obj.status == LicenseStatus.LOCKED.value:
            raise LicenseServiceError("locked", "License đã bị admin khóa", 403)
        if sync_license_status(license_obj, now) == LicenseStatus.EXPIRED.value:
            raise LicenseServiceError("expired", "Tất cả thiết bị của license đã hết hạn", 403)

    def _lease_payload(self, db: Session, license_obj: License, connected: list[str], app_version: str, now: datetime) -> dict:
        active = [item for item in license_obj.devices if device_status(item, now) == "active"]
        if not active:
            raise LicenseServiceError("expired", "Tất cả thiết bị của license đã hết hạn", 403)
        expiries = [as_utc(item.expires_at) for item in active if item.expires_at]
        nearest_expiry = min(expiries)
        latest_expiry = max(expiries)
        lease_expires = min(latest_expiry, now + timedelta(hours=max(1, min(self.settings.lease_hours, 24))))
        allowed = [item.hardware_serial for item in active]
        allowed_set = set(allowed)
        connected_allowed_count = len(allowed_set.intersection(connected))
        minimum = self._minimum_version(db)
        rows_by_serial = {item.hardware_serial: item for item in license_obj.devices}
        all_serials = sorted(set(rows_by_serial) | set(connected))
        return {
            "schema_version": 2,
            "license_id": license_obj.id,
            "customer_name": license_obj.customer.name,
            "license_status": license_obj.status,
            # Legacy summary keys remain during the coordinated client rollout.
            "duration_days": max((item.term_days for item in license_obj.devices), default=0),
            "max_devices": len(license_obj.devices),
            "assigned_device_count": len(license_obj.devices),
            "active_device_count": len(active),
            "expired_device_count": sum(device_status(item, now) == "expired" for item in license_obj.devices),
            "connected_allowed_count": connected_allowed_count,
            "issued_at": iso(now),
            "subscription_expires_at": iso(latest_expiry),
            "lease_expires_at": iso(lease_expires),
            "nearest_device_expires_at": iso(nearest_expiry),
            "latest_device_expires_at": iso(latest_expiry),
            "minimum_client_version": minimum,
            "update_required": version_too_old(app_version, minimum),
            "allowed_serials": sorted(allowed),
            "devices": [
                {
                    "hardware_serial": serial,
                    "allowed": serial in allowed_set,
                    "connected": serial in connected,
                    "status": device_status(rows_by_serial[serial], now) if serial in rows_by_serial else "unassigned",
                    "starts_at": iso(rows_by_serial[serial].starts_at) if serial in rows_by_serial and rows_by_serial[serial].starts_at else None,
                    "expires_at": iso(rows_by_serial[serial].expires_at) if serial in rows_by_serial and rows_by_serial[serial].expires_at else None,
                    "remaining_seconds": max(0, int((as_utc(rows_by_serial[serial].expires_at) - now).total_seconds())) if serial in rows_by_serial and rows_by_serial[serial].expires_at else 0,
                }
                for serial in all_serials
            ],
        }

    def _signed(self, payload: dict, refresh_token: str | None = None) -> dict:
        return {"payload": payload, "signature": sign_payload(self.signing_key, payload), "refresh_token": refresh_token}

    def activate(self, db: Session, *, key: str, installation_id: str, app_version: str, serials: list[str], ip_address: str) -> dict:
        now = utcnow()
        connected = normalize_serials(serials)
        license_obj = self._license_by_key(db, key.strip())
        if not license_obj.customer.is_active:
            raise LicenseServiceError("locked", "Khách hàng đã bị admin khóa", 403)
        if license_obj.status == LicenseStatus.LOCKED.value:
            raise LicenseServiceError("locked", "License đã bị admin khóa", 403)
        eligible_set = {
            item.hardware_serial
            for item in license_obj.devices
            if device_status(item, now) in {"pending", "active"}
        }
        if not license_obj.devices:
            raise LicenseServiceError("no_devices", "License chưa được admin cấp hardware serial", 403)
        if not eligible_set.intersection(connected):
            raise LicenseServiceError("no_approved_device", "Cần kết nối ít nhất một thiết bị còn quyền sử dụng", 403)
        if license_obj.activated_at is None:
            license_obj.activated_at = now
            for item in license_obj.devices:
                if item.starts_at is None or item.expires_at is None:
                    item.starts_at = now
                    item.expires_at = now + timedelta(days=item.term_days)
            license_obj.status = LicenseStatus.ACTIVE.value
        self._validate_license(license_obj, now)

        refresh_token = generate_refresh_token()
        activation = next(
            (
                item
                for item in license_obj.activations
                if item.installation_id == installation_id
            ),
            None,
        )
        if activation is None:
            activation = Activation(license=license_obj, installation_id=installation_id)
            db.add(activation)
        activation.refresh_token_hash = token_fingerprint(
            refresh_token, self.settings.license_key_pepper
        )
        activation.app_version = app_version
        activation.ip_address = ip_address
        activation.connected_serials = json.dumps(connected)
        activation.last_seen_at = now
        activation.revoked_at = None
        for item in license_obj.devices:
            if item.hardware_serial in connected:
                item.last_seen_at = now
        payload = self._lease_payload(db, license_obj, connected, app_version, now)
        db.commit()
        return self._signed(payload, refresh_token)

    def heartbeat(self, db: Session, *, refresh_token: str, installation_id: str, app_version: str, serials: list[str], ip_address: str) -> dict:
        now = utcnow()
        connected = normalize_serials(serials)
        activation = self._activation_by_token(db, refresh_token, installation_id)
        license_obj = activation.license
        self._validate_license(license_obj, now)
        activation.last_seen_at = now
        activation.app_version = app_version
        activation.ip_address = ip_address
        activation.connected_serials = json.dumps(connected)
        for item in license_obj.devices:
            if item.hardware_serial in connected:
                item.last_seen_at = now
        payload = self._lease_payload(db, license_obj, connected, app_version, now)
        db.commit()
        return self._signed(payload)

    def deactivate(self, db: Session, *, refresh_token: str, installation_id: str) -> None:
        activation = self._activation_by_token(db, refresh_token, installation_id)
        activation.revoked_at = utcnow()
        db.commit()
