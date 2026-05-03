"""add email_marketing_consent and email_marketing_consent_at to users

Revision ID: add_email_mkt_consent
Revises: fix_history_sync_completed, rename_sub_price_cents
Create Date: 2026-05-03

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "add_email_mkt_consent"
down_revision: Union[str, Sequence[str], None] = (
    "fix_history_sync_completed",
    "rename_sub_price_cents",
)
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "email_marketing_consent",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.add_column(
        "users",
        sa.Column(
            "email_marketing_consent_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("users", "email_marketing_consent_at")
    op.drop_column("users", "email_marketing_consent")
