from sqlmodel import Field, SQLModel, Relationship
from datetime import datetime, timezone
import sqlalchemy as sa
from sqlalchemy import Index
from db.users import Users

FINISHED = "finished"
STARTED = "started"
CANCELLED = "cancelled"

# Stop reasons for incomplete scans
STOP_REASON_USER_CANCELLED = "user_cancelled"
STOP_REASON_RATE_LIMITED = "rate_limited"
STOP_REASON_MONTHLY_CAP = "monthly_cap"
STOP_REASON_GMAIL_EXPIRED = "gmail_expired"
STOP_REASON_ERROR = "error"


class TaskRuns(SQLModel, table=True):
    __tablename__ = "processing_task_runs"
    id: int = Field(default=None, primary_key=True)
    user_id: str = Field(foreign_key="users.user_id", index=True)
    created: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), nullable=False)
    updated: datetime = Field(
        sa_column_kwargs={"onupdate": sa.func.now()},
        default_factory=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    status: str = Field(nullable=False)
    stop_reason: str | None = Field(default=None, nullable=True)  # Why the scan stopped (if not completed)
    total_emails: int = 0
    processed_emails: int = 0
    applications_found: int = 0
    history_sync_completed: bool = Field(default=False, nullable=False)
    scan_start_date: datetime | None = Field(default=None, nullable=True)
    scan_end_date: datetime | None = Field(default=None, nullable=True)
    last_processed_date: datetime | None = Field(default=None, nullable=True)  # Latest email date scanned (for incremental)
    gmail_query: str | None = Field(default=None, nullable=True)  # Exact q= string sent to Gmail API

    user: Users = Relationship()

    __table_args__ = (
        Index(
            "ix_user_id_status_started_unique",
            "user_id",
            unique=True,
            postgresql_where=(sa.column("status") == STARTED),
        ),
    )
