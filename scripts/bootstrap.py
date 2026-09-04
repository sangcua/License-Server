from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sqlalchemy import select

from app.config import get_settings
from app.database import SessionLocal
from app.models import AdminUser, Base, SystemSetting
from app.database import engine
from app.security import hash_password, load_or_create_signing_key, public_key_pem


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    args = parser.parse_args()
    if len(args.password) < 12:
        raise SystemExit("Mật khẩu admin cần ít nhất 12 ký tự")
    settings = get_settings()
    Base.metadata.create_all(engine)
    key = load_or_create_signing_key(settings.signing_private_key_path)
    public_path = Path(settings.signing_private_key_path).with_name("ed25519-public.pem")
    public_path.write_bytes(public_key_pem(key))
    with SessionLocal() as db:
        admin = db.scalar(select(AdminUser).where(AdminUser.username == args.username))
        if admin is None:
            db.add(AdminUser(username=args.username, password_hash=hash_password(args.password)))
        else:
            admin.password_hash = hash_password(args.password)
            admin.is_active = True
        row = db.get(SystemSetting, "min_client_version") or SystemSetting(key="min_client_version")
        row.value = settings.min_client_version
        db.add(row)
        db.commit()
    print(f"Đã tạo/cập nhật admin {args.username}. Public key: {public_path}")


if __name__ == "__main__":
    main()
