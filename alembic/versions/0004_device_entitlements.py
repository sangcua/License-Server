"""Move subscription terms from licenses to individual devices.

Revision ID: 0004
Revises: 0003
"""

from alembic import op
import sqlalchemy as sa


revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("license_devices", sa.Column("term_days", sa.Integer(), nullable=True))
    op.add_column("license_devices", sa.Column("starts_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("license_devices", sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("license_devices", sa.Column("granted_at", sa.DateTime(timezone=True), nullable=True))

    # Existing customers keep exactly the subscription dates they already own.
    op.execute(
        """
        UPDATE license_devices AS d
        SET term_days = l.duration_days,
            starts_at = CASE WHEN l.activated_at IS NOT NULL THEN l.activated_at ELSE NULL END,
            expires_at = CASE WHEN l.activated_at IS NOT NULL THEN l.expires_at ELSE NULL END,
            granted_at = COALESCE(l.created_at, CURRENT_TIMESTAMP)
        FROM licenses AS l
        WHERE d.license_id = l.id
        """
    )
    op.alter_column("license_devices", "term_days", nullable=False)
    op.alter_column("license_devices", "granted_at", nullable=False)
    op.create_index("ix_license_devices_starts_at", "license_devices", ["starts_at"])
    op.create_index("ix_license_devices_expires_at", "license_devices", ["expires_at"])

    op.drop_column("licenses", "expires_at")
    op.drop_column("licenses", "max_devices")
    op.drop_column("licenses", "duration_days")


def downgrade() -> None:
    op.add_column("licenses", sa.Column("duration_days", sa.Integer(), nullable=True))
    op.add_column("licenses", sa.Column("max_devices", sa.Integer(), nullable=True))
    op.add_column("licenses", sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True))
    op.execute(
        """
        UPDATE licenses AS l
        SET duration_days = COALESCE((SELECT MAX(d.term_days) FROM license_devices d WHERE d.license_id = l.id), 1),
            max_devices = COALESCE((SELECT COUNT(*) FROM license_devices d WHERE d.license_id = l.id), 1),
            expires_at = (SELECT MAX(d.expires_at) FROM license_devices d WHERE d.license_id = l.id)
        """
    )
    op.alter_column("licenses", "duration_days", nullable=False)
    op.alter_column("licenses", "max_devices", nullable=False)
    op.drop_index("ix_license_devices_expires_at", table_name="license_devices")
    op.drop_index("ix_license_devices_starts_at", table_name="license_devices")
    op.drop_column("license_devices", "granted_at")
    op.drop_column("license_devices", "expires_at")
    op.drop_column("license_devices", "starts_at")
    op.drop_column("license_devices", "term_days")
