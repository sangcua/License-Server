"""Initial license schema.

Revision ID: 0001
Revises:
"""
from alembic import op
import sqlalchemy as sa


revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "admin_users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(80), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("failed_attempts", sa.Integer(), nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True)),
        sa.Column("last_login_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("username"),
    )
    op.create_index("ix_admin_users_username", "admin_users", ["username"], unique=True)
    op.create_table(
        "customers",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("notes", sa.Text(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("name"),
    )
    op.create_index("ix_customers_name", "customers", ["name"], unique=True)
    op.create_table(
        "licenses",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("customer_id", sa.Integer(), sa.ForeignKey("customers.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("duration_days", sa.Integer(), nullable=False),
        sa.Column("max_devices", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("key_prefix", sa.String(20), nullable=False),
        sa.Column("key_fingerprint", sa.String(64), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True)),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("key_fingerprint"),
    )
    op.create_index("ix_licenses_customer_id", "licenses", ["customer_id"])
    op.create_index("ix_licenses_status", "licenses", ["status"])
    op.create_index("ix_licenses_key_prefix", "licenses", ["key_prefix"])
    op.create_index("ix_licenses_key_fingerprint", "licenses", ["key_fingerprint"], unique=True)
    op.create_index("ix_licenses_expires_at", "licenses", ["expires_at"])
    op.create_table(
        "license_devices",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("license_id", sa.Integer(), sa.ForeignKey("licenses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("hardware_serial", sa.String(160), nullable=False),
        sa.Column("alias", sa.String(160), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("hardware_serial", name="uq_license_device_serial"),
    )
    op.create_index("ix_license_devices_license_id", "license_devices", ["license_id"])
    op.create_index("ix_license_devices_hardware_serial", "license_devices", ["hardware_serial"])
    op.create_table(
        "activations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("license_id", sa.Integer(), sa.ForeignKey("licenses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("installation_id", sa.String(80), nullable=False),
        sa.Column("refresh_token_hash", sa.String(64), nullable=False),
        sa.Column("app_version", sa.String(40), nullable=False),
        sa.Column("ip_address", sa.String(80), nullable=False),
        sa.Column("connected_serials", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("license_id", "installation_id", name="uq_activation_installation"),
        sa.UniqueConstraint("refresh_token_hash"),
    )
    op.create_index("ix_activations_license_id", "activations", ["license_id"])
    op.create_index("ix_activations_installation_id", "activations", ["installation_id"])
    op.create_index("ix_activations_refresh_token_hash", "activations", ["refresh_token_hash"], unique=True)
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("admin_user_id", sa.Integer(), sa.ForeignKey("admin_users.id", ondelete="SET NULL")),
        sa.Column("action", sa.String(80), nullable=False),
        sa.Column("entity_type", sa.String(40), nullable=False),
        sa.Column("entity_id", sa.String(80), nullable=False),
        sa.Column("details", sa.Text(), nullable=False),
        sa.Column("ip_address", sa.String(80), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_audit_logs_admin_user_id", "audit_logs", ["admin_user_id"])
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])
    op.create_table(
        "system_settings",
        sa.Column("key", sa.String(80), primary_key=True),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("system_settings")
    op.drop_table("audit_logs")
    op.drop_table("activations")
    op.drop_table("license_devices")
    op.drop_table("licenses")
    op.drop_table("customers")
    op.drop_table("admin_users")
