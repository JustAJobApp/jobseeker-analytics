"""rename monthly_price_cents to subscription_price_cents on users

Revision ID: rename_monthly_to_subscription_price
Revises: rename_contributions_to_payments
Create Date: 2026-03-29

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = 'rename_monthly_to_subscription_price'
down_revision: Union[str, None] = 'rename_contributions_to_payments'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column('users', 'monthly_price_cents', new_column_name='subscription_price_cents')


def downgrade() -> None:
    op.alter_column('users', 'subscription_price_cents', new_column_name='monthly_price_cents')
