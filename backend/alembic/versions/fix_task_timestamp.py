"""fix task updated timestamp and support chaining

Revision ID: fix_task_timestamp
Revises: add_always_open_fields
Create Date: 2026-03-07
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'fix_task_timestamp'
down_revision = 'add_always_open_fields' # Links to the previous task run migration
branch_labels = None
depends_on = None

def upgrade():
    # 1. Fix the 'updated' column to use a proper server-side default
    # This ensures PostgreSQL handles the timestamp even if Python fails to send it.
    op.alter_column('processing_task_runs', 'updated',
               existing_type=sa.DateTime(timezone=True),
               server_default=sa.func.now(),
               existing_nullable=False)

def downgrade():
    op.drop_index('ix_user_id_status_started_unique', table_name='processing_task_runs')
    op.alter_column('processing_task_runs', 'updated',
               existing_type=sa.DateTime(timezone=True),
               server_default=None,
               existing_nullable=False)