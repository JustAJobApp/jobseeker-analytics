"""add monthly email tracking fields to users

Revision ID: add_monthly_email_tracking
Revises: add_always_open_fields
Create Date: 2026-03-14

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "add_monthly_email_tracking"
down_revision: Union[str, None] = "add_always_open_fields"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add monthly email cap tracking columns to the users table."""

    op.add_column(
        "users",
        sa.Column(
            "emails_processed_this_month",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )

    op.add_column(
        "users",
        sa.Column(
            "monthly_emails_reset_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )


def downgrade() -> None:
    """Remove monthly email cap tracking columns from the users table."""
    op.drop_column("users", "monthly_emails_reset_at")
    op.drop_column("users", "emails_processed_this_month")
