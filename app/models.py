from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class LicenseStatus(str, Enum):
    READY = "ready"
    ACTIVE = "active"
    LOCKED = "locked"
    EXPIRED = "expired"


class AdminUser(Base):
    __tablename__ = "admin_users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Customer(Base):
    __tablename__ = "customers"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(160), unique=True, index=True)
    notes: Mapped[str] = mapped_column(Text, default="")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    license: Mapped["License | None"] = relationship(
        back_populates="customer", uselist=False
    )


class License(Base):
    __tablename__ = "licenses"
    __table_args__ = (
        UniqueConstraint("customer_id", name="uq_license_customer"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    customer_id: Mapped[int] = mapped_column(ForeignKey("customers.id", ondelete="RESTRICT"), index=True)
    duration_days: Mapped[int] = mapped_column(Integer)
    max_devices: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(20), default=LicenseStatus.READY.value, index=True)
    key_prefix: Mapped[str] = mapped_column(String(20), index=True)
    key_fingerprint: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    customer: Mapped[Customer] = relationship(back_populates="license")
    devices: Mapped[list["LicenseDevice"]] = relationship(back_populates="license", cascade="all, delete-orphan")
    activations: Mapped[list["Activation"]] = relationship(back_populates="license", cascade="all, delete-orphan")


class LicenseDevice(Base):
    __tablename__ = "license_devices"
    __table_args__ = (UniqueConstraint("hardware_serial", name="uq_license_device_serial"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    license_id: Mapped[int] = mapped_column(ForeignKey("licenses.id", ondelete="CASCADE"), index=True)
    hardware_serial: Mapped[str] = mapped_column(String(160), index=True)
    alias: Mapped[str] = mapped_column(String(160), default="")
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    license: Mapped[License] = relationship(back_populates="devices")


class Activation(Base):
    __tablename__ = "activations"
    __table_args__ = (UniqueConstraint("license_id", "installation_id", name="uq_activation_installation"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    license_id: Mapped[int] = mapped_column(ForeignKey("licenses.id", ondelete="CASCADE"), index=True)
    installation_id: Mapped[str] = mapped_column(String(80), index=True)
    refresh_token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    app_version: Mapped[str] = mapped_column(String(40), default="")
    ip_address: Mapped[str] = mapped_column(String(80), default="")
    connected_serials: Mapped[str] = mapped_column(Text, default="[]")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    license: Mapped[License] = relationship(back_populates="activations")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    admin_user_id: Mapped[int | None] = mapped_column(ForeignKey("admin_users.id", ondelete="SET NULL"), index=True)
    action: Mapped[str] = mapped_column(String(80), index=True)
    entity_type: Mapped[str] = mapped_column(String(40), default="")
    entity_id: Mapped[str] = mapped_column(String(80), default="")
    details: Mapped[str] = mapped_column(Text, default="{}")
    ip_address: Mapped[str] = mapped_column(String(80), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class SystemSetting(Base):
    __tablename__ = "system_settings"
    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
