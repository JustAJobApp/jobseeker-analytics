from sqlmodel import Field, SQLModel, Relationship
from datetime import datetime, timezone
import sqlalchemy as sa
from db.users import Users

FINISHED = "finished"
STARTED = "started"
CANCELLED = "cancelled"


class TaskRuns(SQLModel, table=True):
    __tablename__ = "processing_task_runs"
    user_id: str = Field(foreign_key="users.user_id", primary_key=True)
    created: datetime = Field(default_factory=datetime.now, nullable=False)
    updated: datetime = Field(
        sa_column_kwargs={"onupdate": sa.func.now()},
        default_factory=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    status: str = Field(nullable=False)
    total_emails: int = 0
    processed_emails: int = 0

    user: Users = Relationship()
