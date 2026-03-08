"""Background email fetching service that operates without HTTP Request context.

This service enables scheduled email sync (e.g., every 12 hours) for users with
"Always Open" enabled, using only database-stored state.
"""

import logging
from typing import Optional, Tuple
from datetime import datetime, timezone

from sqlmodel import Session, select

from db.users import Users
from db import processing_tasks as task_models
from db.utils.user_email_utils import create_user_email
from db.utils.user_utils import get_last_email_date
from utils.auth_utils import AuthenticatedUser
from utils.billing_utils import SyncPolicy
from utils.email_utils import get_email_ids, get_email, decode_subject_line
from utils.llm_utils import process_email
from utils.task_utils import get_active_task
from utils.config_utils import get_settings
from utils.credential_service import get_credentials_for_background_task
from start_date.storage import get_start_date_email_filter
from constants import QUERY_APPLIED_EMAIL_FILTER
import database

logger = logging.getLogger(__name__)
settings = get_settings()


class BackgroundEmailFetcher:
    """Handles email fetching for background/scheduled tasks without HTTP context."""

    def __init__(self, db_session: Session, user_id: str):
        self.db_session = db_session
        self.user_id = user_id
        self.user: Optional[Users] = None
        self.policy: Optional[SyncPolicy] = None # Central policy instance

    def _load_user(self) -> Optional[Users]:
        """Load user from database."""
        self.user = self.db_session.exec(
            select(Users).where(Users.user_id == self.user_id)
        ).first()
        return self.user

    def fetch_emails(self, last_updated: Optional[datetime] = None) -> bool:
        """Fetch emails and auto-chain next batch if premium."""
        logger.info("BackgroundEmailFetcher starting for user_id: %s", self.user_id)
        try:
            if not self.user:
                self._load_user()
            
            if not self.user:
                logger.error("User %s not found in database", self.user_id)
                return False

            # 1. Initialize Policy to manage tiers and safety limits
            self.policy = SyncPolicy(self.user, self.db_session)

            # 2. Check if user has quota remaining to start
            if not self.policy.can_start_new_task():
                logger.info("User %s has reached their quota. Background sync skipped.", self.user_id)
                return True

            creds = get_credentials_for_background_task(self.db_session, self.user_id)
            if not creds:
                logger.warning("No valid credentials found for user %s", self.user_id)
                return False

            auth_user = AuthenticatedUser(
                creds,
                _user_id=self.user_id,
                _user_email=self.user.user_email if self.user else None,
            )

            # 3. Process the current batch and track results
            processed_count, total_found = self._fetch_emails_impl(auth_user, last_updated)

            # 4. Handle Chaining: Spawn next batch immediately if premium
            if self.policy.should_chain(processed_count, total_found):
                logger.info("Premium chaining: Starting next batch for user %s", self.user_id)
                # Recalculate incremental point for the next batch
                new_last_updated = get_last_email_date(self.user_id, self.db_session)
                return self.fetch_emails(new_last_updated) # Recursive call

            # Update final sync timestamp only after full backlog is cleared
            self.user.last_background_sync_at = datetime.now(timezone.utc)
            self.db_session.add(self.user)
            self.db_session.commit()
            return True

        except Exception as e:
            logger.error("Background fetch failed for user %s: %s", self.user_id, e)
            self._mark_task_cancelled()
            return False

    def _fetch_emails_impl(
        self,
        user: AuthenticatedUser,
        last_updated: Optional[datetime] = None,
    ) -> Tuple[int, int]:
        """Core processing logic constrained by technical and tier limits."""
        gmail_instance = user.service
        
        # Always create or retrieve an active historical record
        process_task_run = self._get_or_create_task_run()
        if not process_task_run:
            return 0, 0

        # Use Policy to enforce the 30-day floor for free users
        effective_start = self.policy.get_effective_start_date()
        start_date_query = get_start_date_email_filter(effective_start.strftime("%Y/%m/%d"))

        # Build Gmail query
        query = start_date_query
        if last_updated:
            additional_time = last_updated.strftime("%Y/%m/%d")
            query = f"{QUERY_APPLIED_EMAIL_FILTER} after:{additional_time}"

        messages = get_email_ids(query=query, gmail_instance=gmail_instance, user_id=self.user_id)
        if not messages:
            process_task_run.status = task_models.FINISHED
            self.db_session.commit()
            return 0, 0

        process_task_run.total_emails = len(messages)
        # Determine allowed limit (capped at 100 for server safety)
        batch_limit = self.policy.get_batch_limit()

        email_records = []
        processed_this_run = 0

        for idx, message in enumerate(messages):
            processed_this_run = idx + 1
            if processed_this_run > batch_limit:
                # Stop batch to protect 0.25 vCPU instance RAM
                processed_this_run -= 1 # Adjust to actual count
                break
                
            msg_id = message["id"]
            logger.info(
                "user_id:%s Background processing email %d of %d",
                self.user_id, processed_this_run, len(messages)
            )

            msg = get_email(
                message_id=msg_id,
                gmail_instance=gmail_instance,
                user_email=user.user_email,
            )

            if msg:
                try:
                    # Process with LLM
                    result = process_email(msg["text_content"], self.user_id, self.db_session)
                    
                    if result and result.get("job_application_status", "").lower().strip() != "false positive":
                        message_data = {
                            "id": msg_id,
                            "company_name": result.get("company_name", "unknown"),
                            "application_status": result.get("job_application_status", "unknown"),
                            "received_at": msg.get("date", "unknown"),
                            "subject": decode_subject_line(msg.get("subject", "unknown")),
                            "job_title": result.get("job_title", "unknown"),
                            "from": msg.get("from", "unknown"),
                        }
                        email_record = create_user_email(self.user_id, message_data, self.db_session)
                        if email_record:
                            email_records.append(email_record)
                except Exception as e:
                    logger.error("Error processing email %s: %s", msg_id, e)

            # Save progress incrementally
            process_task_run.processed_emails = processed_this_run
            process_task_run.applications_found = len(email_records)
            self.db_session.add(process_task_run)
            self.db_session.commit()

        # Batch save extracted records
        if email_records:
            self.db_session.add_all(email_records)
            self.db_session.commit()

        process_task_run.status = task_models.FINISHED
        self.db_session.commit()
        return processed_this_run, len(messages)

    def _get_or_create_task_run(self) -> Optional[task_models.TaskRuns]:
        """Ensures a new record for every background batch to maintain history."""
        active_task = get_active_task(self.user_id, self.db_session)
        if active_task:
            return active_task

        # Create fresh historical record
        process_task_run = task_models.TaskRuns(
            user_id=self.user_id,
            status=task_models.STARTED
        )
        self.db_session.add(process_task_run)
        self.db_session.commit()
        self.db_session.refresh(process_task_run)
        return process_task_run

    def _mark_task_cancelled(self) -> None:
        """Cleanup active task on error."""
        try:
            active = get_active_task(self.user_id, self.db_session)
            if active:
                active.status = task_models.CANCELLED
                self.db_session.commit()
                logger.info("Marked background task as CANCELLED for user_id %s", self.user_id)
        except Exception as e:
            logger.error("Failed to mark task cancelled: %s", e)


def run_background_fetch_for_user(user_id: str) -> bool:
    """Convenience wrapper for single-user background sync."""
    with database.get_session() as db_session:
        last_updated = get_last_email_date(user_id, db_session)
        fetcher = BackgroundEmailFetcher(db_session, user_id)
        return fetcher.fetch_emails(last_updated)