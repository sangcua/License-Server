from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import Settings
from app.models import Base, Customer, License, LicenseDevice, LicenseStatus
from app.security import generate_license_key, token_fingerprint
from app.service import LicenseService, LicenseServiceError, as_utc, device_status, sync_license_status, utcnow


@pytest.fixture()
def setup(tmp_path):
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    settings = Settings(database_url="sqlite+pysqlite:///:memory:", app_secret="test-secret", license_key_pepper="test-pepper", signing_private_key_path=tmp_path / "private.pem", min_client_version="1.3.0")
    key = Ed25519PrivateKey.generate()
    return engine, settings, key, LicenseService(settings, key)


def make_license(db: Session, settings: Settings, serials=("SERIAL-1",), duration=30):
    raw_key = generate_license_key()
    item = License(customer=Customer(name="Khách A"), key_prefix=raw_key[:13], key_fingerprint=token_fingerprint(raw_key, settings.license_key_pepper))
    item.devices = [LicenseDevice(hardware_serial=serial, term_days=duration) for serial in serials]
    db.add(item)
    db.commit()
    return item, raw_key


def test_first_activation_starts_all_pending_devices_once(setup):
    engine, settings, _, service = setup
    with Session(engine) as db:
        item, key = make_license(db, settings, serials=("SERIAL-1", "SERIAL-2"))
        first = service.activate(db, key=key, installation_id="installation-123456", app_version="1.3.0", serials=["SERIAL-1"], ip_address="127.0.0.1")
        activated_at = as_utc(item.activated_at)
        assert item.status == LicenseStatus.ACTIVE.value
        assert first["payload"]["schema_version"] == 2
        assert first["payload"]["allowed_serials"] == ["SERIAL-1", "SERIAL-2"]
        for device in item.devices:
            assert as_utc(device.starts_at) == activated_at
            assert timedelta(days=29, hours=23) < as_utc(device.expires_at) - activated_at <= timedelta(days=30)

        service.activate(db, key=key, installation_id="installation-123456", app_version="1.3.0", serials=["SERIAL-1"], ip_address="127.0.0.1")
        assert as_utc(item.activated_at) == activated_at
        assert len(item.activations) == 1


def test_activation_requires_connected_nonexpired_device(setup):
    engine, settings, _, service = setup
    with Session(engine) as db:
        item, key = make_license(db, settings)
        with pytest.raises(LicenseServiceError) as caught:
            service.activate(db, key=key, installation_id="installation-123456", app_version="1.3.0", serials=["OTHER"], ip_address="127.0.0.1")
        assert caught.value.code == "no_approved_device"
        item.activated_at = utcnow() - timedelta(days=40)
        item.devices[0].starts_at = utcnow() - timedelta(days=40)
        item.devices[0].expires_at = utcnow() - timedelta(days=10)
        item.status = LicenseStatus.EXPIRED.value
        db.commit()
        with pytest.raises(LicenseServiceError) as caught:
            service.activate(db, key=key, installation_id="installation-123456", app_version="1.3.0", serials=["SERIAL-1"], ip_address="127.0.0.1")
        assert caught.value.code == "no_approved_device"


def test_payload_enforces_each_device_expiry(setup):
    engine, settings, _, service = setup
    now = utcnow()
    with Session(engine) as db:
        item, key = make_license(db, settings, serials=("ACTIVE", "EXPIRED"))
        item.activated_at = now - timedelta(days=10)
        item.devices[0].starts_at = now - timedelta(days=10)
        item.devices[0].expires_at = now + timedelta(days=20)
        item.devices[1].starts_at = now - timedelta(days=40)
        item.devices[1].expires_at = now - timedelta(days=10)
        item.status = LicenseStatus.ACTIVE.value
        db.commit()
        response = service.activate(db, key=key, installation_id="installation-123456", app_version="1.3.0", serials=["ACTIVE"], ip_address="127.0.0.1")
        payload = response["payload"]
        assert payload["allowed_serials"] == ["ACTIVE"]
        assert payload["assigned_device_count"] == 2
        assert payload["active_device_count"] == 1
        assert payload["expired_device_count"] == 1
        rows = {row["hardware_serial"]: row for row in payload["devices"]}
        assert rows["ACTIVE"]["allowed"] is True
        assert rows["EXPIRED"]["status"] == "expired"
        assert rows["EXPIRED"]["allowed"] is False


def test_heartbeat_lock_and_unlock_keeps_token(setup):
    engine, settings, _, service = setup
    with Session(engine) as db:
        item, key = make_license(db, settings)
        response = service.activate(db, key=key, installation_id="installation-123456", app_version="1.3.0", serials=["SERIAL-1"], ip_address="127.0.0.1")
        item.status = LicenseStatus.LOCKED.value
        db.commit()
        with pytest.raises(LicenseServiceError) as caught:
            service.heartbeat(db, refresh_token=response["refresh_token"], installation_id="installation-123456", app_version="1.3.0", serials=[], ip_address="127.0.0.1")
        assert caught.value.code == "locked"
        item.status = LicenseStatus.ACTIVE.value
        db.commit()
        recovered = service.heartbeat(db, refresh_token=response["refresh_token"], installation_id="installation-123456", app_version="1.3.0", serials=["SERIAL-1"], ip_address="127.0.0.1")
        assert recovered["payload"]["license_status"] == "active"


def test_expired_license_recovers_with_same_activation_token_after_device_renewal(setup):
    engine, settings, _, service = setup
    with Session(engine) as db:
        item, key = make_license(db, settings)
        response = service.activate(db, key=key, installation_id="installation-123456", app_version="1.3.0", serials=["SERIAL-1"], ip_address="127.0.0.1")
        item.devices[0].expires_at = utcnow() - timedelta(seconds=1)
        item.status = LicenseStatus.EXPIRED.value
        db.commit()
        with pytest.raises(LicenseServiceError) as caught:
            service.heartbeat(db, refresh_token=response["refresh_token"], installation_id="installation-123456", app_version="1.3.0", serials=["SERIAL-1"], ip_address="127.0.0.1")
        assert caught.value.code == "expired"
        item.devices[0].starts_at = utcnow()
        item.devices[0].expires_at = utcnow() + timedelta(days=30)
        item.status = LicenseStatus.ACTIVE.value
        db.commit()
        recovered = service.heartbeat(db, refresh_token=response["refresh_token"], installation_id="installation-123456", app_version="1.3.0", serials=["SERIAL-1"], ip_address="127.0.0.1")
        assert recovered["payload"]["allowed_serials"] == ["SERIAL-1"]


def test_customer_lock_returns_unified_locked_error(setup):
    engine, settings, _, service = setup
    with Session(engine) as db:
        item, key = make_license(db, settings)
        response = service.activate(db, key=key, installation_id="installation-123456", app_version="1.3.0", serials=["SERIAL-1"], ip_address="127.0.0.1")
        item.customer.is_active = False
        db.commit()
        with pytest.raises(LicenseServiceError) as caught:
            service.heartbeat(db, refresh_token=response["refresh_token"], installation_id="installation-123456", app_version="1.3.0", serials=[], ip_address="127.0.0.1")
        assert caught.value.code == "locked"


def test_derived_license_status(setup):
    engine, settings, _, _ = setup
    with Session(engine) as db:
        item, _ = make_license(db, settings)
        assert sync_license_status(item) == "ready"
        item.activated_at = utcnow()
        item.devices[0].starts_at = utcnow() - timedelta(days=2)
        item.devices[0].expires_at = utcnow() - timedelta(days=1)
        assert device_status(item.devices[0]) == "expired"
        assert sync_license_status(item) == "expired"


def test_serial_and_customer_uniqueness(setup):
    engine, settings, _, _ = setup
    with Session(engine) as db:
        make_license(db, settings, serials=("ONE-SERIAL",))
        second_key = generate_license_key()
        db.add(License(customer=Customer(name="Khách B"), key_prefix=second_key[:13], key_fingerprint=token_fingerprint(second_key, settings.license_key_pepper), devices=[LicenseDevice(hardware_serial="ONE-SERIAL", term_days=30)]))
        with pytest.raises(IntegrityError):
            db.commit()
    with Session(engine) as db:
        customer = Customer(name="Một license")
        db.add_all([License(customer=customer, key_prefix="AT-one", key_fingerprint="1" * 64), License(customer=customer, key_prefix="AT-two", key_fingerprint="2" * 64)])
        with pytest.raises(IntegrityError):
            db.commit()


def test_old_client_is_marked_update_required(setup):
    engine, settings, _, service = setup
    with Session(engine) as db:
        _, key = make_license(db, settings)
        response = service.activate(db, key=key, installation_id="installation-123456", app_version="1.2.0", serials=["SERIAL-1"], ip_address="127.0.0.1")
        assert response["payload"]["update_required"] is True
