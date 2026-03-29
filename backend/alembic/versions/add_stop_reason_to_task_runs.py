"""add stop_reason to processing_task_runs

Revision ID: add_stop_reason
Revises: add_scan_date_range
Create Date: 2026-03-17

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "add_stop_reason"
down_revision: Union[str, None] = "add_scan_date_range"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "processing_task_runs",
        sa.Column(
            "stop_reason",
            sa.String(),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("processing_task_runs", "stop_reason")
