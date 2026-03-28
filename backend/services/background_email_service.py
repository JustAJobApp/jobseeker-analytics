"""Background email fetching service that operates without HTTP Request context.

This service enables scheduled email sync (e.g., every 12 hours) for users with
"Always Open" enabled, using only database-stored state.
"""

import logging
from typing import Optional
from datetime import datetime, timezone

from sqlmodel import Session, select

from db.users import Users
from db import processing_tasks as task_models
from db.utils.user_email_utils import create_user_email
from utils.auth_utils import AuthenticatedUser
from utils.email_utils import get_email_ids, get_email, decode_subject_line
from utils.llm_utils import process_email
from utils.task_utils import exceeds_rate_limit
from utils.config_utils import get_settings
from utils.credential_service import get_credentials_for_background_task
from routes.email_routes import build_gmail_query

logger = logging.getLogger(__name__)
settings = get_settings()


class BackgroundEmailFetcher:
    """Handles email fetching for background/scheduled tasks without HTTP context."""

    def __init__(self, db_session: Session, user_id: str):
        self.db_session = db_session
        self.user_id = user_id
        self.user: Optional[Users] = None

    def _load_user(self) -> Optional[Users]:
        """Load user from database."""
        self.user = self.db_session.exec(
            select(Users).where(Users.user_id == self.user_id)
        ).first()
        return self.user

    def _get_start_date_from_db(self) -> Optional[str]:
        """Get start_date from Users table instead of session."""
        if not self.user:
            self._load_user()
        if self.user and self.user.start_date:
            return self.user.start_date.strftime("%Y/%m/%d")
        return None

    def fetch_emails(self, last_updated: Optional[datetime] = None) -> bool:
        """
        Fetch emails for a user without HTTP Request context.

        Args:
            last_updated: Optional datetime to fetch emails after (incremental sync)

        Returns:
            True if successful, False otherwise
        """
        logger.info("BackgroundEmailFetcher starting for user_id: %s", self.user_id)
        try:
            # Load credentials from DB (no session fallback for true background tasks)
            creds = get_credentials_for_background_task(
                self.db_session,
                self.user_id,
            )

            if not creds:
                logger.error(
                    "No valid credentials for background fetch: user_id=%s",
                    self.user_id,
                )
                return False

            # Create AuthenticatedUser with loaded credentials
            auth_user = AuthenticatedUser(
                creds,
                _user_id=self.user_id,
                _user_email=self.user.user_email if self.user else None,
            )

            # Run the email fetch implementation
            self._fetch_emails_impl(auth_user, last_updated)

            # Update last_background_sync_at timestamp
            if not self.user:
                self._load_user()
            if self.user:
                self.user.last_background_sync_at = datetime.now(timezone.utc)
                self.db_session.add(self.user)
                self.db_session.commit()

            return True

        except Exception as e:
            logger.error(
                "Background email fetch failed for user_id %s: %s",
                self.user_id,
                e,
            )
            self._mark_task_cancelled()
            return False

    def _fetch_emails_impl(
        self,
        user: AuthenticatedUser,
        last_updated: Optional[datetime] = None,
    ) -> None:
        """Core email fetching logic without Request dependencies."""
        gmail_instance = user.service

        # Get or create task run
        process_task_run = self._get_or_create_task_run()
        if not process_task_run:
            return

        # Get start_date from DB instead of session
        if not self.user:
            self._load_user()
        start_date = self._get_start_date_from_db()

        query = build_gmail_query(
            last_updated=last_updated,
            start_date_updated=False,
            start_date=start_date,
            scan_end_date=self.user.scan_end_date if self.user else None,
        )
        logger.info("user_id:%s Background fetch query: %s", self.user_id, query)

        messages = get_email_ids(
            query=query,
            gmail_instance=gmail_instance,
            user_id=self.user_id,
        )

        # NOTE: We skip "is_new_user = False" session update - not needed for background tasks
        # Background tasks only run for users who already have credentials stored

        if not messages:
            logger.info(
                "user_id:%s No job application emails found in background fetch.",
                self.user_id,
            )
            process_task_run.status = task_models.FINISHED
            process_task_run.total_emails = 0
            process_task_run.processed_emails = 0
            self.db_session.add(process_task_run)
            self.db_session.commit()
            return

        logger.info(
            "user_id:%s Found %d emails in background fetch.",
            self.user_id,
            len(messages),
        )
        process_task_run.total_emails = len(messages)
        self.db_session.commit()

        email_records = []

        for idx, message in enumerate(messages):
            msg_id = message["id"]
            logger.info(
                "user_id:%s Background processing email %d of %d with id %s",
                self.user_id,
                idx + 1,
                len(messages),
                msg_id,
            )

            process_task_run.processed_emails = idx + 1
            self.db_session.add(process_task_run)
            self.db_session.commit()

            msg = get_email(
                message_id=msg_id,
                gmail_instance=gmail_instance,
                user_email=user.user_email,
            )

            if msg:
                result = None
                try:
                    result = process_email(
                        msg["text_content"],
                        self.user_id,
                        self.db_session,
                    )

                    for key in result.keys():
                        if not result[key]:
                            result[key] = "unknown"
                except Exception as e:
                    logger.error(
                        "user_id:%s Error processing email %d: %s",
                        self.user_id,
                        idx + 1,
                        e,
                    )

                if not isinstance(result, str) and result:
                    if (
                        result.get("job_application_status", "").lower().strip()
                        == "false positive"
                    ):
                        logger.info(
                            "user_id:%s email %d is a false positive, skipping",
                            self.user_id,
                            idx + 1,
                        )
                        continue
                else:
                    result = {
                        "company_name": "unknown",
                        "application_status": "unknown",
                        "job_title": "unknown",
                    }

                message_data = {
                    "id": msg_id,
                    "company_name": result.get("company_name", "unknown"),
                    "application_status": result.get(
                        "job_application_status", "unknown"
                    ),
                    "received_at": msg.get("date", "unknown"),
                    "subject": msg.get("subject", "unknown"),
                    "job_title": result.get("job_title", "unknown"),
                    "from": msg.get("from", "unknown"),
                }
                message_data["subject"] = decode_subject_line(message_data["subject"])

                email_record = create_user_email(
                    self.user_id,
                    message_data,
                    self.db_session,
                )

                if email_record:
                    email_records.append(email_record)
                    process_task_run.applications_found = len(email_records)
                    self.db_session.add(process_task_run)
                    self.db_session.commit()

                    if exceeds_rate_limit(process_task_run.processed_emails):
                        logger.warning(
                            "Rate limit exceeded for user %s at %d emails",
                            self.user_id,
                            process_task_run.processed_emails,
                        )
                        break
            else:
                logger.warning(
                    "user_id:%s Failed to retrieve email content for message %d",
                    self.user_id,
                    idx + 1,
                )

        # Batch insert all records
        if email_records:
            logger.info(
                "Adding %d email records to database for user %s",
                len(email_records),
                self.user_id,
            )
            self.db_session.add_all(email_records)
            self.db_session.commit()
        else:
            logger.info("No new email records to add for user %s", self.user_id)

        process_task_run.status = task_models.FINISHED
        self.db_session.commit()

        logger.info(
            "user_id:%s Background email fetching complete.",
            self.user_id,
        )

    def _get_or_create_task_run(self) -> Optional[task_models.TaskRuns]:
        """Get existing or create new task run for tracking."""
        self.db_session.commit()

        process_task_run = self.db_session.exec(
            select(task_models.TaskRuns)
            .where(task_models.TaskRuns.user_id == self.user_id)
            .order_by(task_models.TaskRuns.updated.desc())
        ).first()

        if process_task_run is None:
            process_task_run = task_models.TaskRuns(
                user_id=self.user_id,
                status=task_models.STARTED,
            )
            self.db_session.add(process_task_run)
            self.db_session.commit()
        else:
            today = datetime.now(timezone.utc).date()
            task_date = (
                process_task_run.updated.date() if process_task_run.updated else None
            )

            if task_date and task_date < today:
                logger.info(
                    "Task was completed on %s, resetting processed emails count",
                    task_date,
                )
                process_task_run.processed_emails = 0
                process_task_run.total_emails = 0
            elif process_task_run.processed_emails >= settings.batch_size_by_env:
                logger.warning(
                    "Already fetched max emails (%s) for user %s today, skipping",
                    settings.batch_size_by_env,
                    self.user_id,
                )
                process_task_run.status = task_models.CANCELLED
                self.db_session.commit()
                return None

        process_task_run.status = task_models.STARTED
        self.db_session.commit()

        return process_task_run

    def _mark_task_cancelled(self) -> None:
        """Mark active task as cancelled on error."""
        try:
            process_task_run = self.db_session.exec(
                select(task_models.TaskRuns).where(
                    task_models.TaskRuns.user_id == self.user_id,
                    task_models.TaskRuns.status == task_models.STARTED,
                )
            ).first()
            if process_task_run:
                process_task_run.status = task_models.CANCELLED
                self.db_session.commit()
                logger.info(
                    "Marked task as CANCELLED for user_id %s",
                    self.user_id,
                )
        except Exception as e:
            logger.error("Failed to mark task cancelled: %s", e)
