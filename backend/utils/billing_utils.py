# backend/utils/billing_utils.py
from datetime import timedelta, timezone, datetime
import logging
from sqlmodel import select

from db.users import Users, CoachClientLink
from utils.config_utils import get_settings
from utils.task_utils import get_lifetime_processed_count

logger = logging.getLogger(__name__)
settings = get_settings()

PREMIUM_CONTRIBUTION_THRESHOLD_CENTS = 500

def get_premium_reason(db_session, user: Users) -> str | None:
    """Determine why a user qualifies for premium tier."""
    if user.role == "coach":
        return "coach"

    active_coach_link = db_session.exec(
        select(CoachClientLink)
        .where(CoachClientLink.client_id == user.user_id)
        .where(CoachClientLink.end_date.is_(None))
    ).first()

    if active_coach_link:
        return "coach_client"

    if (user.monthly_contribution_cents or 0) >= PREMIUM_CONTRIBUTION_THRESHOLD_CENTS:
        return "paid"

    return None

def is_premium_eligible(db_session, user: Users) -> bool:
    """Check if a user qualifies for premium tier."""
    return get_premium_reason(db_session, user) is not None

class SyncPolicy:
    # 1. Hardware Safety: Protect the 0.25 vCPU instance
    # Do NOT use settings.batch_size_by_env here; that is the total ceiling.
    # Keep this at 100 to avoid OOM crashes on Micro instances.
    MAX_BATCH_SIZE = 100 
    
    # 2. Free Tier Limits
    FREE_LOOKBACK_DAYS = 30
    FREE_LIFETIME_LIMIT = 1000

    def __init__(self, user, db_session):
        self.user = user
        self.db = db_session
        # FIX: Pass db_session and user to the check
        self.is_premium = is_premium_eligible(db_session, user)
        self.lifetime_total = get_lifetime_processed_count(user.user_id, db_session)

    def can_start_new_task(self) -> bool:
        """
        MISSING METHOD FIX: Checks if the user has any quota left to begin.
        """
        if self.is_premium:
            # Premium users capped by the infra ceiling (default 10,000)
            return self.lifetime_total < settings.batch_size_by_env
        return self.lifetime_total < self.FREE_LIFETIME_LIMIT

    def get_effective_start_date(self) -> datetime:
        """Enforces the 30-day lookback floor for free users with logging."""
        user_start = self.user.start_date
        
        # Enhanced Logging for debugging
        logger.info(f"SyncPolicy: Evaluating effective start date for user_id: {self.user.user_id}")
        logger.info(f"Original user_start: {user_start}")

        # TIMEZONE AWARENESS FIX: Ensure comparison doesn't crash
        if user_start and user_start.tzinfo is None:
            user_start = user_start.replace(tzinfo=timezone.utc)
            logger.info("Fixed user_start to be timezone-aware (UTC)")
            
        if not user_start:
            user_start = datetime.now(timezone.utc) - timedelta(days=30)
        
        if not self.is_premium:
            thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=self.FREE_LOOKBACK_DAYS)
            # Log the 30-day floor for free users
            logger.info(f"Free tier detected. 30-day floor: {thirty_days_ago}")
            effective_date = max(user_start, thirty_days_ago)
            logger.info(f"Final effective_start for free user: {effective_date}")
            return effective_date
        
        logger.info(f"Premium tier detected. Returning original start date: {user_start}")
        return user_start

    def get_batch_limit(self) -> int:
        """Determines the limit for the current 100-email safety batch."""
        limit = settings.batch_size_by_env if self.is_premium else self.FREE_LIFETIME_LIMIT
        remaining_quota = max(0, limit - self.lifetime_total)
        # Cap at hardware safety limit (100)
        return min(self.MAX_BATCH_SIZE, remaining_quota)

    def should_chain(self, processed_this_run: int, total_found: int) -> bool:
        """Determines if the next batch should trigger immediately."""
        return (self.is_premium and 
                processed_this_run >= self.MAX_BATCH_SIZE and 
                total_found > processed_this_run)
    
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
