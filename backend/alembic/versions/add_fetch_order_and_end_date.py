"""add fetch_order and scan_end_date to users

Revision ID: add_fetch_order_and_end_date
Revises: add_monthly_email_tracking
Create Date: 2026-03-14

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "add_fetch_order_and_end_date"
down_revision: Union[str, None] = "add_monthly_email_tracking"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add fetch_order and scan_end_date columns to the users table."""

    op.add_column(
        "users",
        sa.Column(
            "fetch_order",
            sa.VARCHAR(20),
            nullable=False,
            server_default="recent_first",
        ),
    )

    op.add_column(
        "users",
        sa.Column(
            "scan_end_date",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )


def downgrade() -> None:
    """Remove fetch_order and scan_end_date columns from the users table."""
    op.drop_column("users", "scan_end_date")
    op.drop_column("users", "fetch_order")
