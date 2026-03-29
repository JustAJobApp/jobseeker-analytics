"""add plan and promo_code_used fields to users

Revision ID: add_plan_and_promo_fields
Revises: add_fetch_order_and_end_date
Create Date: 2026-03-15

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "add_plan_and_promo_fields"
down_revision: Union[str, None] = "add_fetch_order_and_end_date"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "plan",
            sa.VARCHAR(20),
            nullable=False,
            server_default="free",
        ),
    )
    op.add_column(
        "users",
        sa.Column(
            "promo_code_used",
            sa.VARCHAR(255),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("users", "promo_code_used")
    op.drop_column("users", "plan")
