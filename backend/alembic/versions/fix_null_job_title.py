"""Fix null job_title in user_emails

Revision ID: fix_null_job_title
Revises: fix_history_sync_completed
Create Date: 2026-03-20

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = "fix_null_job_title"
down_revision = "fix_history_sync_completed"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("UPDATE user_emails SET job_title = 'Unknown' WHERE job_title IS NULL or job_title = 'null' or job_title = ''")


def downgrade():
    pass
