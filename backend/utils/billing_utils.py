"""Billing utilities for premium tier management."""

import logging

from sqlmodel import select, delete

from db.users import Users, CoachClientLink
from db.oauth_credentials import OAuthCredentials

logger = logging.getLogger(__name__)

# Premium tier eligibility threshold (in cents)
PREMIUM_CONTRIBUTION_THRESHOLD_CENTS = 500  # $5/month


def get_premium_reason(db_session, user: Users) -> str | None:
    """
    Determine why a user qualifies for premium tier.

    Returns:
        "coach" if user is a coach
        "coach_client" if user has an active coach
        "paid" if user contributes $5+/month
        None if user doesn't qualify for premium
    """
    if user.role == "coach":
        return "coach"

    active_coach_link = db_session.exec(
        select(CoachClientLink)
        .where(CoachClientLink.client_id == user.user_id)
        .where(CoachClientLink.end_date.is_(None))
    ).first()

    if active_coach_link:
        return "coach_client"

    if user.monthly_contribution_cents >= PREMIUM_CONTRIBUTION_THRESHOLD_CENTS:
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
    - User's contribution reaches $5+/month

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


def downgrade_user_from_premium(db_session, user_id: str) -> bool:
    """
    Check if user should be downgraded from premium tier.

    Called when:
    - CoachClientLink is ended
    - User's contribution drops below $5/month

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
