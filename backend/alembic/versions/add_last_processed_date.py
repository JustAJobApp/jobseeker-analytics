"""add last_processed_date to processing_task_runs

Revision ID: add_last_processed_date
Revises: drop_is_active
Create Date: 2026-03-19

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "add_last_processed_date"
down_revision: Union[str, None] = "drop_is_active"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "processing_task_runs",
        sa.Column(
            "last_processed_date",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("processing_task_runs", "last_processed_date")
