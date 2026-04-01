"""Background job scheduler for Always Open email fetching.

Uses APScheduler to run email sync for premium users at scheduled intervals.
"""

import logging
from typing import List, Optional

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlmodel import select

from db.users import Users
from db import processing_tasks as task_models

from db.oauth_credentials import OAuthCredentials
from db.utils.user_utils import get_last_email_date
from services.background_email_service import BackgroundEmailFetcher
from utils.config_utils import get_settings
import database

logger = logging.getLogger(__name__)
settings = get_settings()

# Global scheduler instance
_scheduler: Optional[BackgroundScheduler] = None


def get_scheduler() -> BackgroundScheduler:
    """Get or create the global scheduler instance."""
    global _scheduler
    if _scheduler is None:
        _scheduler = BackgroundScheduler(
            timezone="UTC",
            job_defaults={
                "coalesce": True,  # Combine missed runs
                "max_instances": 1,  # Only one instance of each job
            },
        )
    return _scheduler


def start_scheduler() -> None:
    """Start the background scheduler with configured jobs."""
    scheduler = get_scheduler()

    if scheduler.running:
        logger.info("Scheduler already running")
        return

    # Add the premium batch job - runs at 3 AM and 3 PM UTC (every 12 hours)
    scheduler.add_job(
        func=run_premium_batch,
        trigger=CronTrigger(hour="3,15", minute=0, timezone="UTC"),
        id="always_open_premium_batch",
        name="Always Open Premium Email Sync (12-hour)",
        replace_existing=True,
    )

    scheduler.start()
    logger.info(
        "Background scheduler started - premium batch runs at 3 AM and 3 PM UTC"
    )


def stop_scheduler() -> None:
    """Gracefully stop the scheduler."""
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=True)
        logger.info("Background scheduler stopped")
    _scheduler = None


def run_premium_batch() -> None:
    """
    Batch job that syncs emails for all users with sync_tier='premium'.

    This runs every 12 hours (3 AM and 3 PM UTC) for premium users:
    - Users with an active coach
    - Users who are coaches
    - Users contributing $5+/month
    """
    logger.info("Starting Always Open premium batch email sync")

    success_count = 0
    error_count = 0
    skipped_count = 0

    with database.get_session() as db_session:
        # Find all eligible premium users
        users = get_eligible_premium_users(db_session)

        if not users:
            logger.info("No premium users eligible for Always Open sync")
            return

        logger.info("Found %d premium users eligible for Always Open sync", len(users))

        for user in users:
            try:
                # Get last_processed_date from task run for accurate incremental fetch
                last_finished = db_session.exec(
                    select(task_models.TaskRuns)
                    .where(task_models.TaskRuns.user_id == user.user_id)
                    .where(task_models.TaskRuns.status == task_models.FINISHED)
                    .where(task_models.TaskRuns.history_sync_completed.is_(True))
                    .order_by(task_models.TaskRuns.updated.desc())
                ).first()
                last_updated = last_finished.last_processed_date if last_finished else get_last_email_date(user.user_id, db_session)

                # Create fetcher and run
                fetcher = BackgroundEmailFetcher(db_session, user.user_id)
                success = fetcher.fetch_emails(last_updated)

                if success:
                    success_count += 1
                    logger.info(
                        "Premium batch: Successfully synced user %s",
                        user.user_id,
                    )
                else:
                    error_count += 1
                    logger.warning(
                        "Premium batch: Failed to sync user %s (no valid credentials)",
                        user.user_id,
                    )

            except Exception as e:
                logger.error(
                    "Premium batch: Error syncing user %s: %s",
                    user.user_id,
                    e,
                )
                error_count += 1

    logger.info(
        "Always Open premium batch complete: %d success, %d errors, %d skipped "
        "out of %d users",
        success_count,
        error_count,
        skipped_count,
        success_count + error_count + skipped_count,
    )


def get_eligible_premium_users(db_session) -> List[Users]:
    """
    Get users eligible for premium background sync.

    Premium tier eligibility:
    1. sync_tier = 'premium' (set automatically for premium users)
    2. Has valid credentials in oauth_credentials table

    Premium users are:
    - Users with active coach (CoachClientLink with no end_date)
    - Users who are coaches (role = 'coach')
    - Users with an active $5+/month subscription (subscription_price_cents >= 500)
    """
    # Query users with premium tier
    eligible_users = db_session.exec(
        select(Users).where(Users.sync_tier == "premium")
    ).all()

    # Filter to only those with valid credentials
    users_with_creds = []
    for user in eligible_users:
        has_creds = db_session.exec(
            select(OAuthCredentials).where(OAuthCredentials.user_id == user.user_id)
        ).first()

        if has_creds:
            users_with_creds.append(user)
        else:
            logger.warning(
                "User %s has premium tier enabled but no credentials stored, skipping",
                user.user_id,
            )

    return users_with_creds
