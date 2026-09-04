from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import Settings
from app.models import Base, Customer, License, LicenseDevice, LicenseStatus
from app.security import generate_license_key, token_fingerprint
from app.service import LicenseService, LicenseServiceError, as_utc, utcnow


@pytest.fixture()
def setup(tmp_path):
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        app_secret="test-secret",
        license_key_pepper="test-pepper",
        signing_private_key_path=tmp_path / "private.pem",
        min_client_version="1.1.0",
    )
    key = Ed25519PrivateKey.generate()
    return engine, settings, key, LicenseService(settings, key)


def make_license(db: Session, settings: Settings, serials=("SERIAL-1",), duration=30, maximum=2):
    raw_key = generate_license_key()
    customer = Customer(name="Khách A")
    item = License(
        customer=customer,
        duration_days=duration,
        max_devices=maximum,
        key_prefix=raw_key[:13],
        key_fingerprint=token_fingerprint(raw_key, settings.license_key_pepper),
    )
    item.devices = [LicenseDevice(hardware_serial=serial) for serial in serials]
    db.add(item)
    db.commit()
    return item, raw_key


def test_activation_starts_duration_and_is_idempotent(setup):
    engine, settings, signing_key, service = setup
    with Session(engine) as db:
        item, key = make_license(db, settings)
        first = service.activate(db, key=key, installation_id="installation-123456", app_version="1.1.0", serials=["SERIAL-1", "UNKNOWN"], ip_address="127.0.0.1")
        activated_at = as_utc(item.activated_at)
        assert item.status == LicenseStatus.ACTIVE.value
        assert timedelta(days=29, hours=23) < as_utc(item.expires_at) - activated_at <= timedelta(days=30)
        assert first["payload"]["allowed_serials"] == ["SERIAL-1"]
        assert first["refresh_token"]

        second = service.activate(db, key=key, installation_id="installation-123456", app_version="1.1.0", serials=["SERIAL-1"], ip_address="127.0.0.1")
        assert as_utc(item.activated_at) == activated_at
        assert len(item.activations) == 1
        assert second["refresh_token"] != first["refresh_token"]


def test_activation_requires_an_approved_connected_serial(setup):
    engine, settings, _, service = setup
    with Session(engine) as db:
        _, key = make_license(db, settings)
        with pytest.raises(LicenseServiceError) as caught:
            service.activate(db, key=key, installation_id="installation-123456", app_version="1.1.0", serials=["OTHER"], ip_address="127.0.0.1")
        assert caught.value.code == "no_approved_device"


def test_heartbeat_lock_and_unlock_keeps_token(setup):
    engine, settings, _, service = setup
    with Session(engine) as db:
        item, key = make_license(db, settings)
        response = service.activate(db, key=key, installation_id="installation-123456", app_version="1.1.0", serials=["SERIAL-1"], ip_address="127.0.0.1")
        heartbeat = service.heartbeat(db, refresh_token=response["refresh_token"], installation_id="installation-123456", app_version="1.1.0", serials=["SERIAL-1"], ip_address="127.0.0.1")
        assert heartbeat["payload"]["customer_name"] == "Khách A"
        assert heartbeat["payload"]["max_devices"] == 2
        assert heartbeat["payload"]["assigned_device_count"] == 1
        assert heartbeat["payload"]["connected_allowed_count"] == 1
        item.status = LicenseStatus.LOCKED.value
        db.commit()
        with pytest.raises(LicenseServiceError) as caught:
            service.heartbeat(db, refresh_token=response["refresh_token"], installation_id="installation-123456", app_version="1.1.0", serials=[], ip_address="127.0.0.1")
        assert caught.value.code == "locked"
        item.status = LicenseStatus.ACTIVE.value
        db.commit()
        recovered = service.heartbeat(db, refresh_token=response["refresh_token"], installation_id="installation-123456", app_version="1.1.0", serials=["SERIAL-1"], ip_address="127.0.0.1")
        assert recovered["payload"]["license_status"] == "active"


def test_customer_lock_returns_unified_locked_error(setup):
    engine, settings, _, service = setup
    with Session(engine) as db:
        item, key = make_license(db, settings)
        response = service.activate(db, key=key, installation_id="installation-123456", app_version="1.1.0", serials=["SERIAL-1"], ip_address="127.0.0.1")
        item.customer.is_active = False
        db.commit()
        with pytest.raises(LicenseServiceError) as caught:
            service.heartbeat(db, refresh_token=response["refresh_token"], installation_id="installation-123456", app_version="1.1.0", serials=[], ip_address="127.0.0.1")
        assert caught.value.code == "locked"


def test_serial_is_unique_across_licenses(setup):
    engine, settings, _, _ = setup
    with Session(engine) as db:
        make_license(db, settings, serials=("ONE-SERIAL",))
        second_key = generate_license_key()
        second = License(customer=Customer(name="Khách B"), duration_days=30, max_devices=1, key_prefix=second_key[:13], key_fingerprint=token_fingerprint(second_key, settings.license_key_pepper), devices=[LicenseDevice(hardware_serial="ONE-SERIAL")])
        db.add(second)
        with pytest.raises(IntegrityError):
            db.commit()


def test_customer_can_have_only_one_license(setup):
    engine, settings, _, _ = setup
    with Session(engine) as db:
        customer = Customer(name="Một license")
        first_key = generate_license_key()
        second_key = generate_license_key()
        db.add_all([
            License(customer=customer, duration_days=30, max_devices=1, key_prefix=first_key[:13], key_fingerprint=token_fingerprint(first_key, settings.license_key_pepper)),
            License(customer=customer, duration_days=30, max_devices=1, key_prefix=second_key[:13], key_fingerprint=token_fingerprint(second_key, settings.license_key_pepper)),
        ])
        with pytest.raises(IntegrityError):
            db.commit()


def test_old_client_is_marked_update_required(setup):
    engine, settings, _, service = setup
    with Session(engine) as db:
        _, key = make_license(db, settings)
        response = service.activate(db, key=key, installation_id="installation-123456", app_version="1.0.0", serials=["SERIAL-1"], ip_address="127.0.0.1")
        assert response["payload"]["update_required"] is True
