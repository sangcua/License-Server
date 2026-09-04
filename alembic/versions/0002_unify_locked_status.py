"""Unify suspended and revoked license statuses as locked.

Revision ID: 0002
Revises: 0001
"""

from alembic import op


revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "UPDATE licenses SET status = 'locked' "
        "WHERE status IN ('suspended', 'revoked')"
    )


def downgrade() -> None:
    # The two legacy states cannot be reconstructed after being unified.
    op.execute("UPDATE licenses SET status = 'suspended' WHERE status = 'locked'")
