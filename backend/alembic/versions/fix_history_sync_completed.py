"""fix history_sync_completed for users with emails

For users who have at least 1 email record, set history_sync_completed=true
on their most recent finished task. This fixes incorrect data from a bug
where incremental scans were incorrectly preserving history_sync_completed=false.

Revision ID: fix_history_sync_completed
Revises: add_last_processed_date
Create Date: 2026-03-20

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "fix_history_sync_completed"
down_revision: Union[str, None] = "add_last_processed_date"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # First, add the history_sync_completed column if it doesn't exist
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = [col['name'] for col in inspector.get_columns('processing_task_runs')]

    if 'history_sync_completed' not in columns:
        op.add_column('processing_task_runs',
            sa.Column('history_sync_completed', sa.Boolean(), nullable=False, server_default='false')
        )

    # Set history_sync_completed=true on the most recent finished task
    # for each user who has at least 1 email record
    op.execute("""
        UPDATE processing_task_runs
        SET history_sync_completed = true
        WHERE id IN (
            SELECT DISTINCT ON (t.user_id) t.id
            FROM processing_task_runs t
            INNER JOIN user_emails e ON e.user_id = t.user_id
            WHERE t.status = 'finished'
            ORDER BY t.user_id, t.updated DESC
        )
    """)


def downgrade() -> None:
    # Cannot reliably restore previous state
    pass
