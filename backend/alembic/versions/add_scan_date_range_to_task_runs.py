"""add scan_start_date and scan_end_date to processing_task_runs

Revision ID: add_scan_date_range
Revises: add_plan_and_promo_fields
Create Date: 2026-03-16

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "add_scan_date_range"
down_revision: Union[str, None] = "add_plan_and_promo_fields"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "processing_task_runs",
        sa.Column(
            "scan_start_date",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "processing_task_runs",
        sa.Column(
            "scan_end_date",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("processing_task_runs", "scan_end_date")
    op.drop_column("processing_task_runs", "scan_start_date")
