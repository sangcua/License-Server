from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.config import get_settings
from app.database import SessionLocal
from app.models import Customer, License, LicenseDevice
from app.security import generate_license_key, token_fingerprint


def main() -> None:
    settings = get_settings()
    with SessionLocal() as db:
        customer = db.scalar(
            select(Customer)
            .where(Customer.name == "Khách Demo")
            .options(selectinload(Customer.license))
        )
        if customer is None:
            customer = Customer(name="Khách Demo", notes="Dữ liệu thử local")
            db.add(customer)
            db.flush()
        elif customer.license is not None:
            print(
                "Khách Demo đã có license. Hãy dùng Web Admin để nâng cấp "
                "hoặc Rotate key nếu cần key mới."
            )
            return
        key = generate_license_key()
        license_obj = License(customer=customer, duration_days=7, max_devices=2, key_prefix=key[:13], key_fingerprint=token_fingerprint(key, settings.license_key_pepper), devices=[LicenseDevice(hardware_serial="DEMO-SERIAL-01", alias="Máy demo")])
        db.add(license_obj)
        db.commit()
        print("License demo đã tạo. Key chỉ hiển thị lần này:")
        print(key)


if __name__ == "__main__":
    main()
