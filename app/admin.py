from __future__ import annotations

import csv
from datetime import timedelta
import io
import json
import secrets
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from .config import Settings
from .database import get_db
from .models import Activation, AdminUser, AuditLog, Customer, License, LicenseDevice, LicenseStatus, SystemSetting
from .rate_limit import MemoryRateLimiter
from .security import generate_license_key, hash_password, token_fingerprint, verify_password
from .service import SERIAL_RE, as_utc, utcnow


def make_admin_router(settings: Settings) -> APIRouter:
    router = APIRouter(prefix="/admin", include_in_schema=False)
    templates = Jinja2Templates(directory=str(__import__("pathlib").Path(__file__).parent / "templates"))
    login_limiter = MemoryRateLimiter()
    tz = ZoneInfo(settings.admin_timezone)

    def csrf(request: Request) -> str:
        value = request.session.get("csrf")
        if not value:
            value = secrets.token_urlsafe(32)
            request.session["csrf"] = value
        return value

    def require_csrf(request: Request, value: str) -> None:
        expected = request.session.get("csrf", "")
        if not expected or not secrets.compare_digest(expected, value):
            raise HTTPException(403, "CSRF token không hợp lệ")

    def current_admin(request: Request, db: Session) -> AdminUser:
        admin_id = request.session.get("admin_id")
        admin = db.get(AdminUser, admin_id) if admin_id else None
        if admin is None or not admin.is_active:
            raise HTTPException(303, headers={"Location": "/admin/login"})
        return admin

    def render(request: Request, name: str, context: dict, status_code: int = 200):
        context.update({"request": request, "csrf_token": csrf(request), "tz": tz, "admin_id": request.session.get("admin_id")})
        return templates.TemplateResponse(request, name, context, status_code=status_code)

    def audit(db: Session, request: Request, admin: AdminUser | None, action: str, entity_type: str = "", entity_id: object = "", details: dict | None = None) -> None:
        db.add(AuditLog(admin_user_id=admin.id if admin else None, action=action, entity_type=entity_type, entity_id=str(entity_id or ""), details=json.dumps(details or {}, ensure_ascii=False), ip_address=request.client.host if request.client else ""))

    def load_license(db: Session, license_id: int, lock: bool = False) -> License:
        stmt = select(License).where(License.id == license_id).options(selectinload(License.customer), selectinload(License.devices), selectinload(License.activations))
        if lock:
            stmt = stmt.with_for_update()
        item = db.scalar(stmt)
        if item is None:
            raise HTTPException(404, "Không tìm thấy license")
        return item

    @router.get("/login", response_class=HTMLResponse)
    def login_page(request: Request):
        return render(request, "login.html", {"error": ""})

    @router.post("/login", response_class=HTMLResponse)
    def login(request: Request, username: str = Form(), password: str = Form(), csrf_token: str = Form(), db: Session = Depends(get_db)):
        require_csrf(request, csrf_token)
        ip = request.client.host if request.client else "unknown"
        if not login_limiter.allow(f"login:{ip}", 5, 300):
            return render(request, "login.html", {"error": "Đăng nhập quá nhiều lần. Hãy thử lại sau."}, 429)
        admin = db.scalar(select(AdminUser).where(func.lower(AdminUser.username) == username.strip().lower()))
        now = utcnow()
        if admin and admin.locked_until and as_utc(admin.locked_until) > now:
            return render(request, "login.html", {"error": "Tài khoản đang tạm khóa."}, 403)
        if not admin or not admin.is_active or not verify_password(admin.password_hash, password):
            if admin:
                admin.failed_attempts += 1
                if admin.failed_attempts >= 5:
                    admin.locked_until = now + timedelta(minutes=15)
                audit(db, request, admin, "admin.login_failed", "admin", admin.id)
                db.commit()
            return render(request, "login.html", {"error": "Sai tài khoản hoặc mật khẩu."}, 401)
        admin.failed_attempts = 0
        admin.locked_until = None
        admin.last_login_at = now
        request.session.clear()
        request.session["admin_id"] = admin.id
        csrf(request)
        audit(db, request, admin, "admin.login", "admin", admin.id)
        db.commit()
        return RedirectResponse("/admin", 303)

    @router.post("/logout")
    def logout(request: Request, csrf_token: str = Form(), db: Session = Depends(get_db)):
        require_csrf(request, csrf_token)
        admin = db.get(AdminUser, request.session.get("admin_id"))
        audit(db, request, admin, "admin.logout")
        db.commit()
        request.session.clear()
        return RedirectResponse("/admin/login", 303)

    @router.get("", response_class=HTMLResponse)
    def dashboard(request: Request, db: Session = Depends(get_db)):
        current_admin(request, db)
        now = utcnow()
        all_licenses = db.scalars(select(License).options(selectinload(License.customer), selectinload(License.devices)).order_by(License.created_at.desc())).all()
        for item in all_licenses:
            if item.expires_at and as_utc(item.expires_at) <= now and item.status in {LicenseStatus.ACTIVE.value, LicenseStatus.LOCKED.value}:
                item.status = LicenseStatus.EXPIRED.value
        db.commit()
        stats = {status.value: 0 for status in LicenseStatus}
        stats[LicenseStatus.READY.value] = sum(item.status == LicenseStatus.READY.value and item.customer.is_active for item in all_licenses)
        stats[LicenseStatus.ACTIVE.value] = sum(item.status == LicenseStatus.ACTIVE.value and item.customer.is_active for item in all_licenses)
        stats[LicenseStatus.LOCKED.value] = sum((item.status == LicenseStatus.LOCKED.value or not item.customer.is_active) and item.status != LicenseStatus.EXPIRED.value for item in all_licenses)
        stats[LicenseStatus.EXPIRED.value] = sum(item.status == LicenseStatus.EXPIRED.value for item in all_licenses)
        stats["expiring"] = sum(bool(item.expires_at and now < as_utc(item.expires_at) <= now + timedelta(days=7)) for item in all_licenses)
        query = request.query_params.get("q", "").strip()
        status_filter = request.query_params.get("status", "").strip()
        licenses = all_licenses
        if query:
            needle = query.casefold()
            licenses = [item for item in licenses if needle in item.customer.name.casefold() or needle in item.key_prefix.casefold() or any(needle in device.hardware_serial.casefold() for device in item.devices)]
        if status_filter == "expiring":
            licenses = [item for item in licenses if item.expires_at and now < as_utc(item.expires_at) <= now + timedelta(days=7)]
        elif status_filter == LicenseStatus.LOCKED.value:
            licenses = [item for item in licenses if (item.status == LicenseStatus.LOCKED.value or not item.customer.is_active) and item.status != LicenseStatus.EXPIRED.value]
        elif status_filter == LicenseStatus.ACTIVE.value:
            licenses = [item for item in licenses if item.status == LicenseStatus.ACTIVE.value and item.customer.is_active]
        elif status_filter in {status.value for status in LicenseStatus}:
            licenses = [item for item in licenses if item.status == status_filter]
        customers = db.scalars(
            select(Customer)
            .options(selectinload(Customer.license).selectinload(License.devices))
            .order_by(Customer.name)
        ).all()
        min_version = db.get(SystemSetting, "min_client_version")
        return render(request, "dashboard.html", {"licenses": licenses, "customers": customers, "stats": stats, "min_version": min_version.value if min_version else settings.min_client_version, "one_time_key": request.session.pop("one_time_key", ""), "query": query, "status_filter": status_filter})

    @router.post("/customers/{customer_id}")
    def update_customer(customer_id: int, request: Request, name: str = Form(), notes: str = Form(""), is_active: str = Form(""), csrf_token: str = Form(), db: Session = Depends(get_db)):
        require_csrf(request, csrf_token)
        admin = current_admin(request, db)
        customer = db.get(Customer, customer_id)
        if customer is None:
            raise HTTPException(404, "Không tìm thấy khách hàng")
        before = {"name": customer.name, "notes": customer.notes, "is_active": customer.is_active}
        customer.name = name.strip()
        customer.notes = notes.strip()
        customer.is_active = is_active == "yes"
        if not customer.name:
            raise HTTPException(400, "Tên khách hàng là bắt buộc")
        after = {"name": customer.name, "notes": customer.notes, "is_active": customer.is_active}
        audit(db, request, admin, "customer.update", "customer", customer.id, {"before": before, "after": after})
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(409, "Tên khách hàng đã tồn tại") from exc
        return RedirectResponse(f"/admin/customers/{customer_id}", 303)

    @router.get("/customers/{customer_id}", response_class=HTMLResponse)
    def customer_detail(customer_id: int, request: Request, db: Session = Depends(get_db)):
        current_admin(request, db)
        customer = db.scalar(
            select(Customer)
            .where(Customer.id == customer_id)
            .options(selectinload(Customer.license).selectinload(License.devices))
        )
        if customer is None:
            raise HTTPException(404, "Không tìm thấy khách hàng")
        return render(request, "customer.html", {"customer": customer})

    @router.post("/licenses")
    def create_license(request: Request, customer_id: str = Form(""), new_customer_name: str = Form(""), new_customer_notes: str = Form(""), duration_days: int = Form(), max_devices: int = Form(), serials: str = Form(""), csrf_token: str = Form(), db: Session = Depends(get_db)):
        require_csrf(request, csrf_token)
        admin = current_admin(request, db)
        customer = None
        if customer_id.strip():
            try:
                customer = db.get(Customer, int(customer_id))
            except ValueError as exc:
                raise HTTPException(400, "Khách hàng không hợp lệ") from exc
            if customer is None:
                raise HTTPException(404, "Không tìm thấy khách hàng")
            if customer.license is not None:
                raise HTTPException(409, "Khách hàng đã có license; hãy dùng chức năng Nâng cấp License")
        elif new_customer_name.strip():
            clean_name = new_customer_name.strip()
            existing_customer = db.scalar(
                select(Customer).where(func.lower(Customer.name) == clean_name.lower())
            )
            if existing_customer is not None:
                return render(
                    request,
                    "confirm_existing_customer.html",
                    {
                        "customer": existing_customer,
                    },
                )
            customer = Customer(name=clean_name, notes=new_customer_notes.strip())
            db.add(customer)
            try:
                db.flush()
            except IntegrityError as exc:
                db.rollback()
                raise HTTPException(409, "Tên khách hàng vừa được tạo ở phiên khác; hãy thử lại") from exc
            audit(db, request, admin, "customer.create_with_license", "customer", customer.id, {"name": customer.name, "notes": customer.notes})
        else:
            raise HTTPException(400, "Tên khách hàng là bắt buộc")
        if not customer.is_active:
            raise HTTPException(400, "Khách hàng đang bị khóa")
        if not (1 <= duration_days <= 36500 and 1 <= max_devices <= 10000):
            raise HTTPException(400, "Số ngày hoặc số thiết bị không hợp lệ")
        parsed = [line.strip() for line in serials.replace(",", "\n").splitlines() if line.strip()]
        parsed = list(dict.fromkeys(parsed))
        if len(parsed) > max_devices:
            raise HTTPException(400, "Danh sách serial vượt giới hạn thiết bị")
        if any(not SERIAL_RE.fullmatch(item) for item in parsed):
            raise HTTPException(400, "Danh sách có hardware serial không hợp lệ")
        raw_key = generate_license_key()
        license_obj = License(customer=customer, duration_days=duration_days, max_devices=max_devices, key_prefix=raw_key[:13], key_fingerprint=token_fingerprint(raw_key, settings.license_key_pepper))
        db.add(license_obj)
        db.flush()
        db.add_all(LicenseDevice(license=license_obj, hardware_serial=item) for item in parsed)
        try:
            db.flush()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(409, "Có serial đã thuộc license khác") from exc
        audit(db, request, admin, "license.create", "license", license_obj.id, {"duration_days": duration_days, "max_devices": max_devices, "serials": parsed})
        db.commit()
        request.session["one_time_key"] = raw_key
        return RedirectResponse(f"/admin/licenses/{license_obj.id}", 303)

    @router.post("/customers/{customer_id}/license/upgrade")
    def upgrade_customer_license(customer_id: int, request: Request, max_devices: int = Form(), extend_days: int = Form(0), serials: str = Form(""), csrf_token: str = Form(), db: Session = Depends(get_db)):
        require_csrf(request, csrf_token)
        admin = current_admin(request, db)
        customer = db.get(Customer, customer_id)
        if customer is None:
            raise HTTPException(404, "Không tìm thấy khách hàng")
        if not customer.is_active:
            raise HTTPException(400, "Khách hàng đang bị khóa")
        item = db.scalar(
            select(License)
            .where(License.customer_id == customer_id)
            .options(selectinload(License.devices), selectinload(License.activations))
            .with_for_update()
        )
        if item is None:
            raise HTTPException(404, "Khách hàng chưa có license")
        if not (1 <= max_devices <= 10000):
            raise HTTPException(400, "Số máy tối đa không hợp lệ")
        if not (0 <= extend_days <= 36500):
            raise HTTPException(400, "Số ngày gia hạn không hợp lệ")

        requested = [line.strip() for line in serials.replace(",", "\n").splitlines() if line.strip()]
        requested = list(dict.fromkeys(requested))
        if any(not SERIAL_RE.fullmatch(serial) for serial in requested):
            raise HTTPException(400, "Danh sách có hardware serial không hợp lệ")
        existing = {device.hardware_serial for device in item.devices}
        additions = [serial for serial in requested if serial not in existing]
        if len(existing) + len(additions) > max_devices:
            raise HTTPException(400, "Số serial sau cập nhật vượt số máy tối đa")
        conflicts = db.scalars(
            select(LicenseDevice).where(LicenseDevice.hardware_serial.in_(additions))
        ).all() if additions else []
        if conflicts:
            conflict_serials = ", ".join(sorted(device.hardware_serial for device in conflicts))
            raise HTTPException(409, f"Serial đã thuộc khách hàng khác: {conflict_serials}")

        before = {
            "max_devices": item.max_devices,
            "duration_days": item.duration_days,
            "expires_at": as_utc(item.expires_at).isoformat() if item.expires_at else None,
            "status": item.status,
            "serials": sorted(existing),
            "key_prefix": item.key_prefix,
        }
        item.max_devices = max_devices
        db.add_all(LicenseDevice(license=item, hardware_serial=serial) for serial in additions)
        now = utcnow()
        if extend_days:
            item.duration_days += extend_days
            if item.expires_at:
                item.expires_at = max(as_utc(item.expires_at), now) + timedelta(days=extend_days)
                if item.status == LicenseStatus.EXPIRED.value:
                    item.status = LicenseStatus.ACTIVE.value
        after = {
            "max_devices": item.max_devices,
            "duration_days": item.duration_days,
            "expires_at": as_utc(item.expires_at).isoformat() if item.expires_at else None,
            "status": item.status,
            "serials": sorted(existing | set(additions)),
            "key_prefix": item.key_prefix,
        }
        audit(db, request, admin, "license.upgrade", "license", item.id, {"before": before, "after": after, "added_serials": additions, "extend_days": extend_days})
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(409, "Có serial vừa được gán ở phiên quản trị khác") from exc
        return RedirectResponse(f"/admin/customers/{customer_id}", 303)

    @router.get("/licenses/{license_id}", response_class=HTMLResponse)
    def license_detail(license_id: int, request: Request, db: Session = Depends(get_db)):
        current_admin(request, db)
        item = load_license(db, license_id)
        audits = db.scalars(select(AuditLog).where(AuditLog.entity_type == "license", AuditLog.entity_id == str(license_id)).order_by(AuditLog.created_at.desc()).limit(100)).all()
        return render(request, "license.html", {"license": item, "audits": audits, "one_time_key": request.session.pop("one_time_key", "")})

    @router.post("/licenses/{license_id}/devices")
    def add_devices(license_id: int, request: Request, serials: str = Form(), aliases: str = Form(""), csrf_token: str = Form(), db: Session = Depends(get_db)):
        require_csrf(request, csrf_token)
        admin = current_admin(request, db)
        item = load_license(db, license_id, True)
        serial_list = [line.strip() for line in serials.replace(",", "\n").splitlines() if line.strip()]
        alias_list = aliases.splitlines()
        serial_list = list(dict.fromkeys(serial_list))
        existing = {device.hardware_serial for device in item.devices}
        additions = [serial for serial in serial_list if serial not in existing]
        if len(existing) + len(additions) > item.max_devices:
            raise HTTPException(400, "Vượt giới hạn thiết bị của license")
        if any(not SERIAL_RE.fullmatch(serial) for serial in additions):
            raise HTTPException(400, "Hardware serial không hợp lệ")
        db.add_all(LicenseDevice(license=item, hardware_serial=serial, alias=alias_list[index].strip() if index < len(alias_list) else "") for index, serial in enumerate(additions))
        try:
            db.flush()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(409, "Có serial đã thuộc license khác; hãy dùng Transfer") from exc
        audit(db, request, admin, "license.devices_add", "license", item.id, {"serials": additions})
        db.commit()
        return RedirectResponse(f"/admin/licenses/{license_id}", 303)

    @router.post("/licenses/{license_id}/devices/import")
    async def import_devices(license_id: int, request: Request, csv_file: UploadFile = File(), csrf_token: str = Form(), db: Session = Depends(get_db)):
        require_csrf(request, csrf_token)
        admin = current_admin(request, db)
        item = load_license(db, license_id, True)
        content = (await csv_file.read()).decode("utf-8-sig")
        rows = list(csv.DictReader(io.StringIO(content)))
        if not rows or "hardware_serial" not in (rows[0].keys() if rows else []):
            raise HTTPException(400, "CSV cần cột hardware_serial và có thể có cột alias")
        existing = {device.hardware_serial for device in item.devices}
        additions: list[tuple[str, str]] = []
        for row in rows:
            serial = str(row.get("hardware_serial") or "").strip()
            if not serial or serial in existing or any(serial == old for old, _ in additions):
                continue
            if not SERIAL_RE.fullmatch(serial):
                raise HTTPException(400, f"Hardware serial không hợp lệ: {serial}")
            additions.append((serial, str(row.get("alias") or "").strip()))
        if len(existing) + len(additions) > item.max_devices:
            raise HTTPException(400, "CSV làm vượt giới hạn thiết bị")
        db.add_all(LicenseDevice(license=item, hardware_serial=serial, alias=alias) for serial, alias in additions)
        try:
            db.flush()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(409, "Có serial đã thuộc license khác; hãy dùng Transfer") from exc
        audit(db, request, admin, "license.devices_import", "license", item.id, {"count": len(additions), "filename": csv_file.filename})
        db.commit()
        return RedirectResponse(f"/admin/licenses/{license_id}", 303)

    @router.post("/licenses/{license_id}/devices/{device_id}/update")
    def update_device(license_id: int, device_id: int, request: Request, alias: str = Form(""), csrf_token: str = Form(), db: Session = Depends(get_db)):
        require_csrf(request, csrf_token)
        admin = current_admin(request, db)
        device = db.get(LicenseDevice, device_id)
        if device is None or device.license_id != license_id:
            raise HTTPException(404, "Không tìm thấy thiết bị")
        device.alias = alias.strip()
        audit(db, request, admin, "license.device_alias", "license", license_id, {"serial": device.hardware_serial, "alias": device.alias})
        db.commit()
        return RedirectResponse(f"/admin/licenses/{license_id}", 303)

    @router.post("/licenses/{license_id}/devices/{device_id}/delete")
    def delete_device(license_id: int, device_id: int, request: Request, csrf_token: str = Form(), db: Session = Depends(get_db)):
        require_csrf(request, csrf_token)
        admin = current_admin(request, db)
        device = db.get(LicenseDevice, device_id)
        if device is None or device.license_id != license_id:
            raise HTTPException(404, "Không tìm thấy thiết bị")
        serial = device.hardware_serial
        db.delete(device)
        audit(db, request, admin, "license.device_remove", "license", license_id, {"serial": serial})
        db.commit()
        return RedirectResponse(f"/admin/licenses/{license_id}", 303)

    @router.post("/licenses/{license_id}/transfer")
    def transfer_device(license_id: int, request: Request, hardware_serial: str = Form(), target_license_id: int = Form(), confirmed: str = Form(""), csrf_token: str = Form(), db: Session = Depends(get_db)):
        require_csrf(request, csrf_token)
        admin = current_admin(request, db)
        if confirmed != "yes":
            raise HTTPException(400, "Transfer cần xác nhận")
        source = load_license(db, license_id, True)
        target = load_license(db, target_license_id, True)
        device = next((row for row in source.devices if row.hardware_serial == hardware_serial.strip()), None)
        if device is None:
            raise HTTPException(404, "Serial không thuộc license nguồn")
        if len(target.devices) >= target.max_devices:
            raise HTTPException(400, "License đích đã đủ thiết bị")
        device.license_id = target.id
        audit(db, request, admin, "license.device_transfer", "license", source.id, {"serial": device.hardware_serial, "to_license": target.id})
        audit(db, request, admin, "license.device_transfer_in", "license", target.id, {"serial": device.hardware_serial, "from_license": source.id})
        db.commit()
        return RedirectResponse(f"/admin/licenses/{target.id}", 303)

    @router.post("/licenses/{license_id}/action")
    def license_action(license_id: int, request: Request, action: str = Form(), days: int = Form(0), csrf_token: str = Form(), db: Session = Depends(get_db)):
        require_csrf(request, csrf_token)
        admin = current_admin(request, db)
        item = load_license(db, license_id, True)
        now = utcnow()
        before = {"status": item.status, "duration_days": item.duration_days, "max_devices": item.max_devices, "expires_at": as_utc(item.expires_at).isoformat() if item.expires_at else None}
        if action == "extend":
            if days < 1:
                raise HTTPException(400, "Số ngày gia hạn phải lớn hơn 0")
            if item.expires_at:
                item.expires_at = max(as_utc(item.expires_at), now) + timedelta(days=days)
                item.duration_days += days
                if item.status == LicenseStatus.EXPIRED.value:
                    item.status = LicenseStatus.ACTIVE.value
            else:
                item.duration_days += days
        elif action in {"lock", "suspend", "revoke"}:
            # Legacy action names are accepted but now mean reversible lock.
            item.status = LicenseStatus.LOCKED.value
        elif action in {"unlock", "resume"}:
            if item.expires_at and as_utc(item.expires_at) <= now:
                item.status = LicenseStatus.EXPIRED.value
            else:
                item.status = LicenseStatus.ACTIVE.value if item.activated_at else LicenseStatus.READY.value
        elif action == "rotate":
            raw_key = generate_license_key()
            item.key_prefix = raw_key[:13]
            item.key_fingerprint = token_fingerprint(raw_key, settings.license_key_pepper)
            for activation in item.activations:
                activation.revoked_at = now
            request.session["one_time_key"] = raw_key
        else:
            raise HTTPException(400, "Thao tác license không hợp lệ")
        after = {"status": item.status, "duration_days": item.duration_days, "max_devices": item.max_devices, "expires_at": as_utc(item.expires_at).isoformat() if item.expires_at else None}
        audit(db, request, admin, f"license.{action}", "license", item.id, {"days": days, "before": before, "after": after})
        db.commit()
        return RedirectResponse(f"/admin/licenses/{license_id}", 303)

    @router.post("/licenses/{license_id}/settings")
    def update_license_settings(license_id: int, request: Request, duration_days: int = Form(), max_devices: int = Form(), csrf_token: str = Form(), db: Session = Depends(get_db)):
        require_csrf(request, csrf_token)
        admin = current_admin(request, db)
        item = load_license(db, license_id, True)
        if not (1 <= duration_days <= 36500 and 1 <= max_devices <= 10000):
            raise HTTPException(400, "Số ngày hoặc số thiết bị không hợp lệ")
        if max_devices < len(item.devices):
            raise HTTPException(400, "Số máy tối đa không được nhỏ hơn số serial đã gán")
        if item.activated_at is not None and duration_days != item.duration_days:
            raise HTTPException(400, "License đã kích hoạt chỉ có thể gia hạn bằng cách cộng thêm ngày")
        before = {"duration_days": item.duration_days, "max_devices": item.max_devices}
        item.duration_days = duration_days
        item.max_devices = max_devices
        after = {"duration_days": item.duration_days, "max_devices": item.max_devices}
        audit(db, request, admin, "license.settings", "license", item.id, {"before": before, "after": after})
        db.commit()
        return RedirectResponse(f"/admin/licenses/{license_id}", 303)

    @router.get("/licenses/{license_id}/devices.csv")
    def export_devices(license_id: int, request: Request, db: Session = Depends(get_db)):
        current_admin(request, db)
        item = load_license(db, license_id)
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["hardware_serial", "alias", "last_seen_at"])
        for device in item.devices:
            writer.writerow([device.hardware_serial, device.alias, device.last_seen_at.isoformat() if device.last_seen_at else ""])
        return StreamingResponse(iter(["\ufeff" + output.getvalue()]), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="license-{license_id}-devices.csv"'})

    @router.post("/settings")
    def update_settings(request: Request, min_client_version: str = Form(), csrf_token: str = Form(), db: Session = Depends(get_db)):
        require_csrf(request, csrf_token)
        admin = current_admin(request, db)
        value = min_client_version.strip()
        if not value:
            raise HTTPException(400, "Phiên bản tối thiểu không được trống")
        row = db.get(SystemSetting, "min_client_version") or SystemSetting(key="min_client_version")
        row.value = value
        db.add(row)
        audit(db, request, admin, "settings.min_client_version", "setting", "min_client_version", {"value": value})
        db.commit()
        return RedirectResponse("/admin", 303)

    return router
