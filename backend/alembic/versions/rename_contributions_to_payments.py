"""rename contributions table to payments and update user billing field names

Revision ID: rename_contributions_to_payments
Revises: rename_payment_intent_to_checkout_session
Create Date: 2026-03-28

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = 'rename_contributions_to_payments'
down_revision: Union[str, None] = 'rename_payment_intent_to_checkout_session'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Rename contributions table to payments
    op.rename_table('contributions', 'payments')

    # Rename user billing fields
    op.alter_column('users', 'monthly_contribution_cents', new_column_name='monthly_price_cents')
    op.alter_column('users', 'contribution_started_at', new_column_name='subscribed_at')
    op.alter_column('users', 'total_contributed_cents', new_column_name='total_paid_cents')


def downgrade() -> None:
    op.alter_column('users', 'total_paid_cents', new_column_name='total_contributed_cents')
    op.alter_column('users', 'subscribed_at', new_column_name='contribution_started_at')
    op.alter_column('users', 'monthly_price_cents', new_column_name='monthly_contribution_cents')

    op.rename_table('payments', 'contributions')
