from sqlmodel import SQLModel, Field
from datetime import datetime, timezone
from typing import Optional
import uuid
import sqlalchemy as sa


class Contributions(SQLModel, table=True):
    """Tracks payment history for user contributions."""

    __tablename__ = "contributions"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    user_id: str = Field(foreign_key="users.user_id", nullable=False, index=True)

    # Stripe identifiers
    stripe_checkout_session_id: Optional[str] = Field(default=None, nullable=True)
    stripe_subscription_id: Optional[str] = Field(default=None, nullable=True)

    # Payment details
    amount_cents: int = Field(nullable=False)
    is_recurring: bool = Field(nullable=False)

    # Status: 'pending', 'completed', 'failed', 'refunded', 'cancelled'
    status: str = Field(nullable=False)

    # What triggered this payment
    trigger_type: Optional[str] = Field(default=None, nullable=True)

    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at: datetime = Field(
        sa_column_kwargs={"onupdate": sa.func.now()},
        default_factory=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
