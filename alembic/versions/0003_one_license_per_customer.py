"""Enforce one license per customer and remove empty duplicate licenses.

Revision ID: 0003
Revises: 0002
"""

from __future__ import annotations

import json

from alembic import op
import sqlalchemy as sa


revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    connection = op.get_bind()
    duplicate_customer_ids = connection.execute(
        sa.text(
            "SELECT customer_id FROM licenses GROUP BY customer_id "
            "HAVING COUNT(*) > 1 ORDER BY customer_id"
        )
    ).scalars().all()

    for customer_id in duplicate_customer_ids:
        rows = connection.execute(
            sa.text(
                """
                SELECT l.id, l.max_devices, l.activated_at,
                       (SELECT COUNT(*) FROM activations a WHERE a.license_id = l.id) AS activation_count,
                       (SELECT COUNT(*) FROM license_devices d WHERE d.license_id = l.id) AS device_count
                FROM licenses l
                WHERE l.customer_id = :customer_id
                ORDER BY CASE WHEN l.activated_at IS NULL THEN 1 ELSE 0 END, l.id
                """
            ),
            {"customer_id": customer_id},
        ).mappings().all()
        meaningful = [
            row
            for row in rows
            if row["activated_at"] is not None
            or row["activation_count"]
            or row["device_count"]
        ]
        if len(meaningful) > 1:
            ids = ", ".join(str(row["id"]) for row in meaningful)
            raise RuntimeError(
                f"Customer {customer_id} has multiple non-empty licenses ({ids}); "
                "resolve them manually before migration 0003"
            )
        primary = meaningful[0] if meaningful else rows[0]
        extras = [row for row in rows if row["id"] != primary["id"]]
        unsafe = [
            row
            for row in extras
            if row["activated_at"] is not None
            or row["activation_count"]
            or row["device_count"]
        ]
        if unsafe:
            ids = ", ".join(str(row["id"]) for row in unsafe)
            raise RuntimeError(
                f"Customer {customer_id} has unsafe duplicate licenses ({ids}); "
                "resolve them manually before migration 0003"
            )

        new_max_devices = max(int(row["max_devices"]) for row in rows)
        connection.execute(
            sa.text("UPDATE licenses SET max_devices = :maximum WHERE id = :license_id"),
            {"maximum": new_max_devices, "license_id": primary["id"]},
        )
        for extra in extras:
            details = json.dumps(
                {
                    "customer_id": customer_id,
                    "primary_license_id": primary["id"],
                    "removed_license_id": extra["id"],
                    "primary_max_devices_after": new_max_devices,
                    "reason": "empty_unactivated_duplicate",
                },
                ensure_ascii=False,
            )
            connection.execute(
                sa.text(
                    """
                    INSERT INTO audit_logs
                        (admin_user_id, action, entity_type, entity_id, details, ip_address, created_at)
                    VALUES
                        (NULL, 'license.consolidate_removed', 'license', :entity_id, :details, 'migration', CURRENT_TIMESTAMP)
                    """
                ),
                {"entity_id": str(extra["id"]), "details": details},
            )
            connection.execute(
                sa.text("DELETE FROM licenses WHERE id = :license_id"),
                {"license_id": extra["id"]},
            )

    op.create_unique_constraint(
        "uq_license_customer", "licenses", ["customer_id"]
    )


def downgrade() -> None:
    op.drop_constraint("uq_license_customer", "licenses", type_="unique")
