from sqlmodel import SQLModel, Field
from pydantic import BaseModel
from datetime import datetime, timezone
from typing import Optional
import sqlalchemy as sa
import uuid

class UserData(BaseModel):
    user_id: str
    user_email: str
    start_date: datetime

class Users(SQLModel, table=True):
    __tablename__ = "users"
    user_id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key = True)
    user_email: str = Field(nullable=False)
    start_date: datetime = Field(nullable=True) # Start date for job applications
    # Billing fields
    stripe_customer_id: str | None = Field(default=None, nullable=True)
    # Add role field to distinguish generic users from coaches
    role: str = Field(default="") # '' (unset) | 'jobseeker' | 'coach'
    # Onboarding fields
    onboarding_completed_at: datetime | None = Field(default=None, nullable=True)  # When start date was set
    # Email sync fields (separate from signup auth)
    has_email_sync_configured: bool = Field(default=False, nullable=False)
    sync_email_address: str | None = Field(default=None, nullable=True)  # Email address being synced (can differ from user_email)
    # Subscription billing fields
    monthly_price_cents: int = Field(default=0, nullable=False)  # 0 = free user
    subscribed_at: datetime | None = Field(default=None, nullable=True)  # When they first paid
    total_paid_cents: int = Field(default=0, nullable=False)  # Lifetime payments
    stripe_subscription_id: str | None = Field(default=None, nullable=True)  # For subscription management
    # Background sync fields
    sync_tier: str = Field(default="none", nullable=False)  # 'none' or 'premium'
    last_background_sync_at: datetime | None = Field(default=None, nullable=True)  # Last background sync timestamp
    # Monthly email processing cap tracking
    emails_processed_this_month: int = Field(default=0, nullable=False)
    monthly_emails_reset_at: datetime | None = Field(default=None, nullable=True)
    # Scan preferences
    fetch_order: str = Field(default="recent_first", nullable=False)
    scan_end_date: datetime | None = Field(default=None, nullable=True)
    # Plan / promo
    plan: str = Field(default="free", nullable=False)  # 'free' | 'promo' | 'paid'
    promo_code_used: str | None = Field(default=None, nullable=True)

class CoachClientLink(SQLModel, table=True):
    __tablename__ = "coach_client_link"
    coach_id: str = Field(foreign_key="users.user_id", primary_key=True)
    client_id: str = Field(foreign_key="users.user_id", primary_key=True)
    start_date: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    # If NULL, the relationship is currently active.
    end_date: Optional[datetime] = Field(default=None, nullable=True)
    created: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), nullable=False)
    updated: datetime = Field(
        sa_column_kwargs={"onupdate": sa.func.now()},
        default_factory=lambda: datetime.now(timezone.utc),
        nullable=False,
    )