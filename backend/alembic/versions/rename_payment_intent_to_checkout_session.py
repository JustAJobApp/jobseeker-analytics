"""rename stripe_payment_intent_id to stripe_checkout_session_id in contributions

Revision ID: rename_payment_intent_to_checkout_session
Revises: make_job_title_nullable
Create Date: 2026-03-28

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = 'rename_payment_intent_to_checkout_session'
down_revision: Union[str, None] = 'make_job_title_nullable'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column(
        'contributions',
        'stripe_payment_intent_id',
        new_column_name='stripe_checkout_session_id',
    )


def downgrade() -> None:
    op.alter_column(
        'contributions',
        'stripe_checkout_session_id',
        new_column_name='stripe_payment_intent_id',
    )
