"""Billing utilities for premium tier management."""

import logging

from sqlmodel import select

from db.users import Users, CoachClientLink

logger = logging.getLogger(__name__)

# Monthly subscription price for premium tier (in cents)
PREMIUM_MONTHLY_PRICE_CENTS = 500  # $5/month


def get_premium_reason(db_session, user: Users) -> str | None:
    """
    Determine why a user qualifies for premium tier.

    Returns:
        "coach" if user is a coach
        "coach_client" if user has an active coach
        "paid" if user has an active $5+/month subscription
        None if user doesn't qualify for premium
    """
    if user.plan == "promo":
        return "promo"

    if user.role == "coach":
        return "coach"

    active_coach_link = db_session.exec(
        select(CoachClientLink)
        .where(CoachClientLink.client_id == user.user_id)
        .where(CoachClientLink.end_date.is_(None))
    ).first()

    if active_coach_link:
        return "coach_client"

    if user.subscription_price_cents >= PREMIUM_MONTHLY_PRICE_CENTS:
        return "paid"

    return None


def is_premium_eligible(db_session, user: Users) -> bool:
    """Check if a user qualifies for premium tier."""
    return get_premium_reason(db_session, user) is not None


def upgrade_user_to_premium(db_session, user_id: str) -> bool:
    """
    Upgrade a user to premium tier if they're eligible.

    Called when:
    - CoachClientLink is created
    - User's subscription reaches $5+/month

    Returns True if upgraded, False otherwise.
    """
    user = db_session.get(Users, user_id)
    if not user:
        logger.warning("Cannot upgrade user %s - not found", user_id)
        return False

    if is_premium_eligible(db_session, user):
        if user.sync_tier != "premium":
            user.sync_tier = "premium"
            db_session.add(user)
            db_session.commit()
            logger.info("Upgraded user %s to premium tier", user_id)
            return True
        else:
            logger.info("User %s already has premium tier", user_id)

    return False


def get_monthly_email_cap(db_session, user: Users) -> int:
    """Return this user's monthly email processing cap. Free=500, Premium=5000."""
    from utils.tier_limits import FREE_MONTHLY_EMAIL_CAP, PRO_MONTHLY_EMAIL_CAP
    if is_premium_eligible(db_session, user):
        return PRO_MONTHLY_EMAIL_CAP
    return FREE_MONTHLY_EMAIL_CAP


def reset_monthly_counter_if_needed(user: Users) -> Users:
    """Reset emails_processed_this_month if we're in a new calendar month."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    if user.monthly_emails_reset_at:
        reset_dt = user.monthly_emails_reset_at
        if reset_dt.tzinfo is None:
            reset_dt = reset_dt.replace(tzinfo=timezone.utc)
        if (now.year, now.month) > (reset_dt.year, reset_dt.month):
            user.emails_processed_this_month = 0
            user.monthly_emails_reset_at = now
    else:
        user.monthly_emails_reset_at = now
    return user


def downgrade_user_from_premium(db_session, user_id: str) -> bool:
    """
    Check if user should be downgraded from premium tier.

    Called when:
    - CoachClientLink is ended
    - User's subscription drops below $5/month

    Returns True if downgraded, False otherwise.
    """
    user = db_session.get(Users, user_id)
    if not user:
        logger.warning("Cannot check downgrade for user %s - not found", user_id)
        return False

    if not is_premium_eligible(db_session, user):
        if user.sync_tier == "premium":
            user.sync_tier = "none"
            db_session.add(user)
            db_session.commit()
            logger.info("Downgraded user %s from premium tier", user_id)
            return True

    return False
