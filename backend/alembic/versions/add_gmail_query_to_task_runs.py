"""add gmail_query to processing_task_runs

Revision ID: add_gmail_query_to_task_runs
Revises: make_job_title_nullable
Create Date: 2026-03-28

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "add_gmail_query_to_task_runs"
down_revision: Union[str, None] = "make_job_title_nullable"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "processing_task_runs",
        sa.Column("gmail_query", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("processing_task_runs", "gmail_query")
