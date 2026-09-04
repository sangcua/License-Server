from datetime import timedelta
import base64
import re

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.middleware.sessions import SessionMiddleware

from app.admin import make_admin_router
from app.api import make_api_router
from app.config import Settings
from app.database import get_db
from app.models import Activation, AdminUser, Base, Customer, License, LicenseDevice, LicenseStatus
from app.security import canonical_json, generate_license_key, hash_password, token_fingerprint
from app.service import LicenseService, as_utc, device_status, utcnow


def make_test_app(tmp_path):
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    settings = Settings(app_secret="session-test-secret", license_key_pepper="pepper", signing_private_key_path=tmp_path / "private.pem", min_client_version="1.3.0")
    signing_key = Ed25519PrivateKey.generate()
    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key=settings.app_secret, same_site="strict")
    app.include_router(make_api_router(LicenseService(settings, signing_key)))
    app.include_router(make_admin_router(settings))

    def test_db():
        with factory() as db:
            yield db

    app.dependency_overrides[get_db] = test_db
    return app, factory, settings, signing_key


def login(client: TestClient) -> str:
    page = client.get("/admin/login")
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    response = client.post("/admin/login", data={"username": "admin", "password": "A-strong-password-123", "csrf_token": csrf})
    assert response.status_code in {200, 303}
    page = client.get("/admin")
    return re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)


def pending_device(serial: str, days: int = 30, alias: str = "") -> LicenseDevice:
    return LicenseDevice(hardware_serial=serial, alias=alias, term_days=days)


def active_device(serial: str, *, starts=None, expires=None, days: int = 30) -> LicenseDevice:
    now = utcnow()
    return LicenseDevice(hardware_serial=serial, term_days=days, starts_at=starts or now, expires_at=expires or now + timedelta(days=days))


def test_activate_and_heartbeat_http_contract(tmp_path):
    app, factory, settings, signing_key = make_test_app(tmp_path)
    key = generate_license_key()
    with factory() as db:
        db.add(License(customer=Customer(name="HTTP Customer"), key_prefix=key[:13], key_fingerprint=token_fingerprint(key, settings.license_key_pepper), devices=[pending_device("PHONE-1")]))
        db.commit()
    client = TestClient(app)
    activated = client.post("/api/v1/license/activate", json={"license_key": key, "installation_id": "installation-http-123", "app_version": "1.3.0", "serials": ["PHONE-1"]})
    assert activated.status_code == 200
    body = activated.json()
    signature = base64.urlsafe_b64decode(body["signature"] + "=" * (-len(body["signature"]) % 4))
    signing_key.public_key().verify(signature, canonical_json(body["payload"]))
    assert body["payload"]["schema_version"] == 2
    assert body["payload"]["devices"][0]["expires_at"]
    heartbeat = client.post("/api/v1/license/heartbeat", json={"refresh_token": body["refresh_token"], "installation_id": "installation-http-123", "app_version": "1.3.0", "serials": ["PHONE-1"]})
    assert heartbeat.json()["payload"]["allowed_serials"] == ["PHONE-1"]


def test_admin_login_uses_csrf_and_argon2(tmp_path):
    app, factory, _, _ = make_test_app(tmp_path)
    with factory() as db:
        db.add(AdminUser(username="admin", password_hash=hash_password("A-strong-password-123")))
        db.commit()
    client = TestClient(app, follow_redirects=False)
    page = client.get("/admin/login")
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    assert client.post("/admin/login", data={"username": "admin", "password": "A-strong-password-123", "csrf_token": "wrong"}).status_code == 403
    accepted = client.post("/admin/login", data={"username": "admin", "password": "A-strong-password-123", "csrf_token": csrf})
    assert accepted.status_code == 303


def test_create_customer_requires_serial_and_has_no_maximum(tmp_path):
    app, factory, _, _ = make_test_app(tmp_path)
    with factory() as db:
        db.add(AdminUser(username="admin", password_hash=hash_password("A-strong-password-123")))
        db.commit()
    client = TestClient(app)
    csrf = login(client)
    dashboard = client.get("/admin")
    assert 'name="max_devices"' not in dashboard.text
    rejected = client.post("/admin/licenses", data={"new_customer_name": "Thiếu máy", "duration_days": "30", "serials": "", "csrf_token": csrf})
    assert rejected.status_code == 400
    created = client.post("/admin/licenses", data={"new_customer_name": "Khách đầu tiên", "duration_days": "30", "serials": "PHONE-1\nPHONE-2", "csrf_token": csrf}, follow_redirects=False)
    assert created.status_code == 303
    with factory() as db:
        item = db.scalar(select(License).join(Customer).where(Customer.name == "Khách đầu tiên"))
        assert len(item.devices) == 2
        assert all(device.term_days == 30 and device.starts_at is None for device in item.devices)


def test_add_later_devices_starts_now_and_keeps_key(tmp_path):
    app, factory, _, _ = make_test_app(tmp_path)
    now = utcnow()
    with factory() as db:
        admin = AdminUser(username="admin", password_hash=hash_password("A-strong-password-123"))
        customer = Customer(name="Khách thêm máy")
        item = License(customer=customer, key_prefix="AT-keep-key", key_fingerprint="k" * 64, activated_at=now - timedelta(days=5), status="active", devices=[active_device("OLD-1", starts=now - timedelta(days=5), expires=now + timedelta(days=25))])
        db.add_all([admin, item]); db.commit(); customer_id, license_id, fingerprint = customer.id, item.id, item.key_fingerprint
    client = TestClient(app, follow_redirects=False)
    csrf = login(client)
    response = client.post(f"/admin/customers/{customer_id}/license/devices", data={"term_days": "30", "serials": "NEW-1\nNEW-2", "aliases": "Mới 1\nMới 2", "csrf_token": csrf})
    assert response.status_code == 303
    with factory() as db:
        item = db.get(License, license_id)
        assert item.key_fingerprint == fingerprint
        new_rows = [row for row in item.devices if row.hardware_serial.startswith("NEW")]
        assert len(new_rows) == 2
        assert all(timedelta(days=29, hours=23) < as_utc(row.expires_at) - as_utc(row.starts_at) <= timedelta(days=30) for row in new_rows)


def test_renew_selected_uses_active_and_expired_formulas(tmp_path):
    app, factory, _, _ = make_test_app(tmp_path)
    now = utcnow()
    with factory() as db:
        admin = AdminUser(username="admin", password_hash=hash_password("A-strong-password-123"))
        customer = Customer(name="Khách gia hạn")
        active = active_device("ACTIVE", starts=now - timedelta(days=5), expires=now + timedelta(days=5))
        expired = active_device("EXPIRED", starts=now - timedelta(days=40), expires=now - timedelta(days=10))
        untouched = active_device("UNTOUCHED", starts=now, expires=now + timedelta(days=20))
        item = License(customer=customer, key_prefix="AT-renew", key_fingerprint="r" * 64, activated_at=now - timedelta(days=40), status="active", devices=[active, expired, untouched])
        db.add_all([admin, item]); db.commit(); customer_id = customer.id
        active_id, expired_id = active.id, expired.id
        old_active_expiry, untouched_expiry = as_utc(active.expires_at), as_utc(untouched.expires_at)
    client = TestClient(app, follow_redirects=False)
    csrf = login(client)
    response = client.post(f"/admin/customers/{customer_id}/license/devices/renew", data={"device_ids": [str(active_id), str(expired_id)], "days": "10", "csrf_token": csrf})
    assert response.status_code == 303
    with factory() as db:
        rows = {row.hardware_serial: row for row in db.scalars(select(LicenseDevice)).all()}
        assert as_utc(rows["ACTIVE"].expires_at) == old_active_expiry + timedelta(days=10)
        assert as_utc(rows["EXPIRED"].expires_at) > now + timedelta(days=9)
        assert rows["EXPIRED"].term_days == 10
        assert as_utc(rows["UNTOUCHED"].expires_at) == untouched_expiry


def test_foreign_serial_is_rejected(tmp_path):
    app, factory, _, _ = make_test_app(tmp_path)
    with factory() as db:
        admin = AdminUser(username="admin", password_hash=hash_password("A-strong-password-123"))
        first = Customer(name="Khách một", license=License(key_prefix="AT-first", key_fingerprint="1" * 64, devices=[pending_device("FIRST-1")]))
        second = Customer(name="Khách hai", license=License(key_prefix="AT-second", key_fingerprint="2" * 64, devices=[pending_device("SECOND-1")]))
        db.add_all([admin, first, second]); db.commit(); customer_id = first.id
    client = TestClient(app, follow_redirects=False)
    csrf = login(client)
    response = client.post(f"/admin/customers/{customer_id}/license/devices", data={"term_days": "30", "serials": "SECOND-1", "csrf_token": csrf})
    assert response.status_code == 409


def test_lock_unlock_preserves_activation(tmp_path):
    app, factory, _, _ = make_test_app(tmp_path)
    now = utcnow()
    with factory() as db:
        admin = AdminUser(username="admin", password_hash=hash_password("A-strong-password-123"))
        item = License(customer=Customer(name="Khách khóa"), status=LicenseStatus.ACTIVE.value, key_prefix="AT-prefix", key_fingerprint="f" * 64, activated_at=now, devices=[active_device("PHONE-1")])
        item.activations.append(Activation(installation_id="installation-lock-test", refresh_token_hash="r" * 64, app_version="1.3.0", ip_address="127.0.0.1", connected_serials="[]"))
        db.add_all([admin, item]); db.commit(); license_id = item.id
    client = TestClient(app, follow_redirects=False)
    csrf = login(client)
    assert client.post(f"/admin/licenses/{license_id}/action", data={"action": "lock", "csrf_token": csrf}).status_code == 303
    assert client.post(f"/admin/licenses/{license_id}/action", data={"action": "unlock", "csrf_token": csrf}).status_code == 303
    with factory() as db:
        item = db.get(License, license_id)
        assert item.status == LicenseStatus.ACTIVE.value
        assert item.activations[0].revoked_at is None
