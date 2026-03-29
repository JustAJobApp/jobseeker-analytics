"""Make job_title nullable in user_emails

Revision ID: make_job_title_nullable
Revises: fix_null_job_title
Create Date: 2026-03-28

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = "make_job_title_nullable"
down_revision = "fix_null_job_title"
branch_labels = None
depends_on = None


def upgrade():
    # First ensure no existing NULLs remain (safety net)
    op.execute("UPDATE user_emails SET job_title = 'Unknown' WHERE job_title IS NULL OR job_title = '' OR job_title = 'null'")
    # Make the column nullable so job_title can legitimately be absent
    op.alter_column('user_emails', 'job_title', nullable=True)


def downgrade():
    # Coalesce any NULLs before restoring NOT NULL constraint
    op.execute("UPDATE user_emails SET job_title = 'Unknown' WHERE job_title IS NULL")
    op.alter_column('user_emails', 'job_title', nullable=False)
