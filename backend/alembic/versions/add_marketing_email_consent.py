"""add marketing_email_consent to users

Revision ID: add_marketing_email_consent
Revises: add_scan_date_range_to_task_runs
Create Date: 2026-03-28

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'add_marketing_email_consent'
down_revision: Union[str, None] = 'add_scan_date_range_to_task_runs'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add marketing_email_consent column to users table."""
    op.add_column('users', sa.Column(
        'marketing_email_consent',
        sa.Boolean(),
        nullable=False,
        server_default=sa.text('false')
    ))


def downgrade() -> None:
    """Remove marketing_email_consent column from users table."""
    op.drop_column('users', 'marketing_email_consent')
