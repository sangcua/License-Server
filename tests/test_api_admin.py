import re

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.middleware.sessions import SessionMiddleware

from app.admin import make_admin_router
from app.api import make_api_router
from app.config import Settings
from app.database import get_db
from app.models import Activation, AdminUser, Base, Customer, License, LicenseDevice, LicenseStatus
from app.security import generate_license_key, hash_password, token_fingerprint
from app.service import LicenseService, as_utc, utcnow
from datetime import timedelta


def make_test_app(tmp_path):
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    settings = Settings(app_secret="session-test-secret", license_key_pepper="pepper", signing_private_key_path=tmp_path / "private.pem")
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


def test_activate_and_heartbeat_http_contract(tmp_path):
    app, factory, settings, signing_key = make_test_app(tmp_path)
    key = generate_license_key()
    with factory() as db:
        db.add(License(customer=Customer(name="HTTP Customer"), duration_days=30, max_devices=1, key_prefix=key[:13], key_fingerprint=token_fingerprint(key, settings.license_key_pepper), devices=[LicenseDevice(hardware_serial="PHONE-1")]))
        db.commit()
    client = TestClient(app)
    activated = client.post("/api/v1/license/activate", json={"license_key": key, "installation_id": "installation-http-123", "app_version": "1.1.0", "serials": ["PHONE-1"]})
    assert activated.status_code == 200
    body = activated.json()
    from app.security import canonical_json
    import base64
    signature = base64.urlsafe_b64decode(body["signature"] + "=" * (-len(body["signature"]) % 4))
    signing_key.public_key().verify(signature, canonical_json(body["payload"]))
    heartbeat = client.post("/api/v1/license/heartbeat", json={"refresh_token": body["refresh_token"], "installation_id": "installation-http-123", "app_version": "1.1.0", "serials": ["PHONE-1"]})
    assert heartbeat.status_code == 200
    assert heartbeat.json()["payload"]["allowed_serials"] == ["PHONE-1"]


def test_admin_login_uses_csrf_and_argon2(tmp_path):
    app, factory, _, _ = make_test_app(tmp_path)
    with factory() as db:
        db.add(AdminUser(username="admin", password_hash=hash_password("A-strong-password-123")))
        db.commit()
    client = TestClient(app, follow_redirects=False)
    page = client.get("/admin/login")
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    rejected = client.post("/admin/login", data={"username": "admin", "password": "A-strong-password-123", "csrf_token": "wrong"})
    assert rejected.status_code == 403
    accepted = client.post("/admin/login", data={"username": "admin", "password": "A-strong-password-123", "csrf_token": csrf})
    assert accepted.status_code == 303
    assert accepted.headers["location"] == "/admin"


def test_first_license_can_create_customer_inline(tmp_path):
    app, factory, _, _ = make_test_app(tmp_path)
    with factory() as db:
        db.add(AdminUser(username="admin", password_hash=hash_password("A-strong-password-123")))
        db.commit()
    client = TestClient(app)
    login_page = client.get("/admin/login")
    login_csrf = re.search(r'name="csrf_token" value="([^"]+)"', login_page.text).group(1)
    client.post("/admin/login", data={"username": "admin", "password": "A-strong-password-123", "csrf_token": login_csrf})
    dashboard = client.get("/admin")
    assert "Tạo khách hàng + License" in dashboard.text
    assert "Tạo khách hàng</button>" not in dashboard.text
    assert 'name="new_customer_name"' in dashboard.text
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', dashboard.text).group(1)
    created = client.post("/admin/licenses", data={"customer_id": "", "new_customer_name": "Khách đầu tiên", "duration_days": "30", "max_devices": "1", "serials": "PHONE-1", "csrf_token": csrf}, follow_redirects=False)
    assert created.status_code == 303
    with factory() as db:
        assert db.query(Customer).filter(Customer.name == "Khách đầu tiên").count() == 1
        assert db.query(License).count() == 1


def test_duplicate_customer_redirects_to_upgrade_without_creating_license(tmp_path):
    app, factory, _, _ = make_test_app(tmp_path)
    with factory() as db:
        customer = Customer(name="Khách hiện có", notes="Đã tạo trước")
        customer.license = License(duration_days=30, max_devices=1, key_prefix="AT-existing", key_fingerprint="e" * 64)
        db.add_all([AdminUser(username="admin", password_hash=hash_password("A-strong-password-123")), customer])
        db.commit()
    client = TestClient(app)
    login_page = client.get("/admin/login")
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', login_page.text).group(1)
    client.post("/admin/login", data={"username": "admin", "password": "A-strong-password-123", "csrf_token": csrf})
    dashboard = client.get("/admin")
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', dashboard.text).group(1)
    duplicate = client.post("/admin/licenses", data={"customer_id": "", "new_customer_name": "KHÁCH HIỆN CÓ", "new_customer_notes": "không ghi đè", "duration_days": "12", "max_devices": "1", "serials": "PHONE-2", "csrf_token": csrf})
    assert duplicate.status_code == 200
    assert "Khách hàng đã tồn tại" in duplicate.text
    assert "Mở trang Nâng cấp License" in duplicate.text
    with factory() as db:
        assert db.query(Customer).count() == 1
        assert db.query(License).count() == 1
        assert db.query(LicenseDevice).filter(LicenseDevice.hardware_serial == "PHONE-2").count() == 0


def test_customer_detail_has_upgrade_flow(tmp_path):
    app, factory, _, _ = make_test_app(tmp_path)
    with factory() as db:
        admin = AdminUser(username="admin", password_hash=hash_password("A-strong-password-123"))
        customer = Customer(name="Khách chi tiết")
        customer.license = License(duration_days=30, max_devices=1, key_prefix="AT-detail", key_fingerprint="d" * 64, devices=[LicenseDevice(hardware_serial="PHONE-1")])
        db.add_all([admin, customer])
        db.commit()
        customer_id = customer.id
    client = TestClient(app)
    login_page = client.get("/admin/login")
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', login_page.text).group(1)
    client.post("/admin/login", data={"username": "admin", "password": "A-strong-password-123", "csrf_token": csrf})
    detail = client.get(f"/admin/customers/{customer_id}")
    assert detail.status_code == 200
    assert "Nâng cấp License" in detail.text
    assert f'action="/admin/customers/{customer_id}/license/upgrade"' in detail.text


def test_upgrade_updates_existing_license_without_changing_key(tmp_path):
    app, factory, _, _ = make_test_app(tmp_path)
    with factory() as db:
        admin = AdminUser(username="admin", password_hash=hash_password("A-strong-password-123"))
        customer = Customer(name="Khách nâng cấp")
        customer.license = License(duration_days=30, max_devices=1, key_prefix="AT-keep-key", key_fingerprint="k" * 64, devices=[LicenseDevice(hardware_serial="PHONE-1")])
        db.add_all([admin, customer])
        db.commit()
        customer_id = customer.id
        license_id = customer.license.id
        fingerprint = customer.license.key_fingerprint
    client = TestClient(app, follow_redirects=False)
    page = client.get("/admin/login")
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    client.post("/admin/login", data={"username": "admin", "password": "A-strong-password-123", "csrf_token": csrf})
    detail = client.get(f"/admin/customers/{customer_id}")
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', detail.text).group(1)
    duplicate_license = client.post("/admin/licenses", data={"customer_id": str(customer_id), "new_customer_name": "", "duration_days": "30", "max_devices": "1", "serials": "", "csrf_token": csrf})
    assert duplicate_license.status_code == 409
    upgraded = client.post(f"/admin/customers/{customer_id}/license/upgrade", data={"max_devices": "4", "extend_days": "0", "serials": "PHONE-1\nPHONE-2", "csrf_token": csrf})
    assert upgraded.status_code == 303
    with factory() as db:
        item = db.get(License, license_id)
        assert db.query(License).filter(License.customer_id == customer_id).count() == 1
        assert item.max_devices == 4
        assert item.key_fingerprint == fingerprint
        assert {device.hardware_serial for device in item.devices} == {"PHONE-1", "PHONE-2"}


def test_upgrade_rejects_too_small_limit_and_foreign_serial(tmp_path):
    app, factory, _, _ = make_test_app(tmp_path)
    with factory() as db:
        admin = AdminUser(username="admin", password_hash=hash_password("A-strong-password-123"))
        first = Customer(name="Khách một")
        first.license = License(duration_days=30, max_devices=2, key_prefix="AT-first", key_fingerprint="1" * 64, devices=[LicenseDevice(hardware_serial="FIRST-1"), LicenseDevice(hardware_serial="FIRST-2")])
        second = Customer(name="Khách hai")
        second.license = License(duration_days=30, max_devices=1, key_prefix="AT-second", key_fingerprint="2" * 64, devices=[LicenseDevice(hardware_serial="SECOND-1")])
        db.add_all([admin, first, second])
        db.commit()
        customer_id = first.id
    client = TestClient(app, follow_redirects=False)
    page = client.get("/admin/login")
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    client.post("/admin/login", data={"username": "admin", "password": "A-strong-password-123", "csrf_token": csrf})
    detail = client.get(f"/admin/customers/{customer_id}")
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', detail.text).group(1)
    too_small = client.post(f"/admin/customers/{customer_id}/license/upgrade", data={"max_devices": "1", "extend_days": "0", "serials": "", "csrf_token": csrf})
    assert too_small.status_code == 400
    conflict = client.post(f"/admin/customers/{customer_id}/license/upgrade", data={"max_devices": "3", "extend_days": "0", "serials": "SECOND-1", "csrf_token": csrf})
    assert conflict.status_code == 409
    with factory() as db:
        item = db.scalar(select(License).where(License.customer_id == customer_id))
        assert item.max_devices == 2
        assert {device.hardware_serial for device in item.devices} == {"FIRST-1", "FIRST-2"}


def test_expired_license_reactivates_only_when_extended(tmp_path):
    app, factory, _, _ = make_test_app(tmp_path)
    now = utcnow()
    with factory() as db:
        admin = AdminUser(username="admin", password_hash=hash_password("A-strong-password-123"))
        customer = Customer(name="Khách hết hạn")
        customer.license = License(duration_days=30, max_devices=1, status=LicenseStatus.EXPIRED.value, key_prefix="AT-expired", key_fingerprint="x" * 64, activated_at=now - timedelta(days=31), expires_at=now - timedelta(days=1), devices=[LicenseDevice(hardware_serial="EXPIRED-1")])
        db.add_all([admin, customer])
        db.commit()
        customer_id = customer.id
        license_id = customer.license.id
        old_expiry = customer.license.expires_at
    client = TestClient(app, follow_redirects=False)
    page = client.get("/admin/login")
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    client.post("/admin/login", data={"username": "admin", "password": "A-strong-password-123", "csrf_token": csrf})
    detail = client.get(f"/admin/customers/{customer_id}")
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', detail.text).group(1)
    unchanged = client.post(f"/admin/customers/{customer_id}/license/upgrade", data={"max_devices": "1", "extend_days": "0", "serials": "", "csrf_token": csrf})
    assert unchanged.status_code == 303
    with factory() as db:
        item = db.get(License, license_id)
        assert item.status == LicenseStatus.EXPIRED.value
        assert as_utc(item.expires_at) == as_utc(old_expiry)
    extended = client.post(f"/admin/customers/{customer_id}/license/upgrade", data={"max_devices": "1", "extend_days": "5", "serials": "", "csrf_token": csrf})
    assert extended.status_code == 303
    with factory() as db:
        item = db.get(License, license_id)
        assert item.status == LicenseStatus.ACTIVE.value
        assert item.duration_days == 35
        assert as_utc(item.expires_at) > now + timedelta(days=4)


def test_admin_lock_unlock_preserves_activation_and_settings_rules(tmp_path):
    app, factory, _, _ = make_test_app(tmp_path)
    now = utcnow()
    with factory() as db:
        admin = AdminUser(username="admin", password_hash=hash_password("A-strong-password-123"))
        item = License(customer=Customer(name="Khách khóa"), duration_days=30, max_devices=2, status=LicenseStatus.ACTIVE.value, key_prefix="AT-prefix", key_fingerprint="f" * 64, activated_at=now, expires_at=now + timedelta(days=30), devices=[LicenseDevice(hardware_serial="PHONE-1")])
        item.activations.append(Activation(installation_id="installation-lock-test", refresh_token_hash="r" * 64, app_version="1.1.0", ip_address="127.0.0.1", connected_serials="[]"))
        db.add_all([admin, item])
        db.commit()
        license_id = item.id
    client = TestClient(app, follow_redirects=False)
    page = client.get("/admin/login")
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    client.post("/admin/login", data={"username": "admin", "password": "A-strong-password-123", "csrf_token": csrf})
    detail = client.get(f"/admin/licenses/{license_id}")
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', detail.text).group(1)

    locked = client.post(f"/admin/licenses/{license_id}/action", data={"action": "lock", "days": "0", "csrf_token": csrf})
    assert locked.status_code == 303
    with factory() as db:
        item = db.get(License, license_id)
        assert item.status == LicenseStatus.LOCKED.value
        assert item.activations[0].revoked_at is None

    unlocked = client.post(f"/admin/licenses/{license_id}/action", data={"action": "unlock", "days": "0", "csrf_token": csrf})
    assert unlocked.status_code == 303
    too_small = client.post(f"/admin/licenses/{license_id}/settings", data={"duration_days": "30", "max_devices": "0", "csrf_token": csrf})
    assert too_small.status_code == 400
    with factory() as db:
        assert db.get(License, license_id).status == LicenseStatus.ACTIVE.value
