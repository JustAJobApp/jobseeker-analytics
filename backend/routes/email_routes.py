from datetime import timezone
import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, Request, HTTPException, BackgroundTasks
from sqlmodel import select, desc
from db.user_emails import UserEmails
from db import processing_tasks as task_models
from db.users import Users
from db.utils.user_email_utils import create_user_email
from db.utils.user_utils import get_last_email_date
from utils.auth_utils import AuthenticatedUser
from utils.billing_utils import SyncPolicy
from utils.email_utils import get_email_ids, get_email, decode_subject_line
from utils.llm_utils import process_email
from utils.task_utils import get_active_task
from utils.config_utils import get_settings
from utils.credential_service import get_credentials_for_background_task
from session.session_layer import validate_session
from utils.onboarding_utils import require_onboarding_complete
from utils.admin_utils import get_context_user_id
import database
from start_date.storage import get_start_date_email_filter
from constants import QUERY_APPLIED_EMAIL_FILTER
from datetime import datetime
from slowapi import Limiter
from slowapi.util import get_remote_address
from utils.job_utils import normalize_job_title

limiter = Limiter(key_func=get_remote_address)

# Logger setup
logger = logging.getLogger(__name__)

# Get settings
settings = get_settings()
APP_URL = settings.APP_URL


# FastAPI router for email routes
router = APIRouter()


@router.get("/processing/status")
@limiter.limit("30/minute")
async def processing_status(
    request: Request,
    db_session: database.DBSession,
    user_id: str = Depends(validate_session),
):
    """Get current email processing status for dashboard polling.

    Returns a structured response with:
    - status: 'idle', 'processing', or 'complete'
    - total_emails: Total emails to process
    - processed_emails: Emails processed so far
    - applications_found: Number of applications extracted
    - last_scan_at: ISO timestamp of last completed scan (null if never scanned)
    - should_rescan: True if >24 hours since last scan
    """
    from sqlmodel import func
    from datetime import timezone

    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    # Get latest task run
    process_task_run = db_session.exec(
        select(task_models.TaskRuns)
        .where(task_models.TaskRuns.user_id == user_id)
        .order_by(task_models.TaskRuns.updated.desc())
    ).first()

    if not process_task_run:
        return {
            "status": "idle",
            "total_emails": 0,
            "processed_emails": 0,
            "applications_found": 0,
            "last_scan_at": None,
            "should_rescan": True  # Never scanned, should scan
        }

    # Determine status
    if process_task_run.status == task_models.FINISHED:
        status = "complete"
    elif process_task_run.status == task_models.STARTED:
        status = "processing"
    else:
        status = "idle"

    # Get applications_found count
    # During processing, use the task run's count (updated in real-time)
    # When complete/idle, query the database for total count
    if status == "processing":
        applications_found = process_task_run.applications_found or 0
    else:
        applications_found = db_session.exec(
            select(func.count(UserEmails.id)).where(
                UserEmails.user_id == user_id
            )
        ).one()

    # Calculate last_scan_at and should_rescan
    # Find the most recent FINISHED task to get last successful scan time
    last_scan_at = None
    should_rescan = True  # Default to true if never completed

    last_finished_task = db_session.exec(
        select(task_models.TaskRuns)
        .where(task_models.TaskRuns.user_id == user_id)
        .where(task_models.TaskRuns.status == task_models.FINISHED)
        .order_by(task_models.TaskRuns.updated.desc())
    ).first()

    if last_finished_task and last_finished_task.updated:
        task_updated = last_finished_task.updated
        # Make timezone-aware if naive
        if task_updated.tzinfo is None:
            task_updated = task_updated.replace(tzinfo=timezone.utc)
        last_scan_at = task_updated.isoformat()
        hours_since_scan = (datetime.now(timezone.utc) - task_updated).total_seconds() / 3600
        should_rescan = hours_since_scan > 24
    elif applications_found > 0:
        # No finished task but have emails - use most recent email date
        most_recent_email = db_session.exec(
            select(func.max(UserEmails.received_at)).where(UserEmails.user_id == user_id)
        ).first()
        if most_recent_email:
            # Make timezone-aware if naive
            if most_recent_email.tzinfo is None:
                most_recent_email = most_recent_email.replace(tzinfo=timezone.utc)
            last_scan_at = most_recent_email.isoformat()
            hours_since_scan = (datetime.now(timezone.utc) - most_recent_email).total_seconds() / 3600
            should_rescan = hours_since_scan > 24

    return {
        "status": status,
        "total_emails": process_task_run.total_emails or 0,
        "processed_emails": process_task_run.processed_emails or 0,
        "applications_found": applications_found,
        "last_scan_at": last_scan_at,
        "should_rescan": should_rescan
    }


@router.post("/processing/start")
@limiter.limit("5/minute")
async def start_processing(
    request: Request,
    background_tasks: BackgroundTasks,
    db_session: database.DBSession,
    user_id: str = Depends(validate_session),
):
    """Manually trigger email scan (refresh button).

    Returns 401 if the user's OAuth token has expired.
    Returns 409 if a scan is already in progress.
    Returns 200 if scan started successfully.
    """
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = db_session.exec(select(Users).where(Users.user_id == user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Check if already processing
    active_task = db_session.exec(
        select(task_models.TaskRuns)
        .where(task_models.TaskRuns.user_id == user_id)
        .where(task_models.TaskRuns.status == task_models.STARTED)
    ).first()

    if active_task:
        raise HTTPException(
            status_code=409,
            detail="already_processing"
        )

    # Load credentials with DB-first approach and session fallback
    try:
        creds = get_credentials_for_background_task(
            db_session,
            user_id
        )

        if not creds:
            raise HTTPException(
                status_code=401,
                detail="token_expired"
            )

        # Check if user has Gmail read scope
        gmail_scope = "https://www.googleapis.com/auth/gmail.readonly"
        if not creds.scopes or gmail_scope not in creds.scopes:
            raise HTTPException(
                status_code=403,
                detail="gmail_scope_missing"
            )

        auth_user = AuthenticatedUser(
            creds, 
            _user_id=user.user_id, 
            _user_email=user.user_email
        )

        # Get the last email date for incremental fetching
        last_updated = get_last_email_date(user_id, db_session)

        background_tasks.add_task(fetch_emails_to_db, auth_user, request, last_updated, user_id=user_id)

        logger.info(f"Manual scan started for user {user_id}")
        return {"message": "Processing started"}
    except HTTPException:
        # Re-raise HTTP exceptions (like gmail_scope_missing) as-is
        raise
    except Exception as e:
        logger.error(f"Error starting scan for user {user_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to start processing")


@router.get("/get-emails", response_model=List[UserEmails])
@limiter.limit("5/minute")
def query_emails(request: Request, db_session: database.DBSession, user_id: str = Depends(get_context_user_id)) -> None:
    try:
        logger.info(f"query_emails for user_id: {user_id}")
        # Query emails sorted by date (newest first)
        db_session.expire_all()  # Clear any cached data
        db_session.commit()  # Commit pending changes to ensure the database is in latest state
        statement = select(UserEmails).where(UserEmails.user_id == user_id).order_by(desc(UserEmails.received_at))
        user_emails = db_session.exec(statement).all()

        for email in user_emails:
            new_job_title = normalize_job_title(email.job_title)
            if email.normalized_job_title != new_job_title:
                email.normalized_job_title = new_job_title
                db_session.add(email)
                db_session.commit()
                logger.info(f"Updated normalized job title for email {email.id} to {new_job_title}")

        # Filter out records with "unknown" application status
        filtered_emails = [
            email for email in user_emails 
            if email.application_status and email.application_status.lower() != "unknown"
        ]

        logger.info(f"Found {len(user_emails)} total emails, returning {len(filtered_emails)} after filtering out 'unknown' status")
        return filtered_emails  # Return filtered list

    except Exception as e:
        logger.error(f"Error fetching emails for user_id {user_id}: {e}")
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")
        

@router.delete("/delete-email/{email_id}")
@limiter.limit("20/minute")
async def delete_email(request: Request, db_session: database.DBSession, email_id: str, user_id: str = Depends(require_onboarding_complete)):
    """
    Delete an email record by its ID for the authenticated user.
    """
    try:
        # Query the email record to ensure it exists and belongs to the user
        email_record = db_session.exec(
            select(UserEmails).where(
                (UserEmails.id == email_id) & (UserEmails.user_id == user_id)
            )
        ).first()

        if not email_record:
            logger.warning(f"Email with id {email_id} not found for user_id {user_id}")
            raise HTTPException(
                status_code=404, detail=f"Email with id {email_id} not found"
            )

        # Delete the email record
        db_session.delete(email_record)
        db_session.commit()

        logger.info(f"Email with id {email_id} deleted successfully for user_id {user_id}")
        return {"message": "Item deleted successfully"}

    except HTTPException as e:
        # Propagate explicit HTTP errors (e.g., 404) without converting to 500
        raise e
    except Exception as e:
        logger.error(f"Error deleting email with id {email_id} for user_id {user_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete email: {str(e)}")
        

def fetch_emails_to_db(
    user: AuthenticatedUser,
    request: Request,
    last_updated: Optional[datetime] = None,
    *,
    user_id: str,
) -> None:
    logger.info(f"fetch_emails_to_db for user_id: {user_id}")
    try:
        _fetch_emails_to_db_impl(user, request, last_updated, user_id=user_id)
    except Exception as e:
        logger.error(f"Error in fetch_emails_to_db for user_id {user_id}: {e}")
        # Mark the task as cancelled so it doesn't stay stuck in "processing"
        try:
            with database.get_session() as db_session:
                process_task_run = db_session.exec(
                    select(task_models.TaskRuns).where(
                        task_models.TaskRuns.user_id == user_id,
                        task_models.TaskRuns.status == task_models.STARTED
                    )
                ).first()
                if process_task_run:
                    process_task_run.status = task_models.CANCELLED
                    db_session.commit()
                    logger.info(f"Marked task as CANCELLED for user_id {user_id}")
        except Exception as cleanup_error:
            logger.error(f"Error cleaning up task for user_id {user_id}: {cleanup_error}")


def _fetch_emails_to_db_impl(
    user_auth: AuthenticatedUser,
    request: Request,
    last_updated: Optional[datetime] = None,
    *,
    user_id: str,
    background_tasks: Optional[BackgroundTasks] = None
) -> None:
    """
    Core implementation for fetching emails with tiered limits and chaining.
    """
    with database.get_session() as db_session:
        user_record = db_session.get(Users, user_id)
        if not user_record:
            logger.error(f"User {user_id} not found in database")
            return

        # 1. Initialize Sync Policy to determine limits and eligibility
        policy = SyncPolicy(user_record, db_session)
        
        if not policy.can_start_new_task():
            logger.info(f"User {user_id} has reached their quota. Skipping task creation.")
            return

        # 2. Prevent duplicate active tasks for the same user
        active_task = get_active_task(user_id, db_session)
        if active_task:
            logger.warning(f"Task already STARTED for user {user_id}. Skipping duplicate run.")
            return

        # 3. Create a NEW historical record for this specific batch run
        process_task_run = task_models.TaskRuns(user_id=user_id, status=task_models.STARTED)
        db_session.add(process_task_run)
        db_session.commit()
        db_session.refresh(process_task_run)

        # 4. Build the Gmail search query based on policy-enforced start date
        effective_start = policy.get_effective_start_date()
        start_date_query = get_start_date_email_filter(effective_start.strftime("%Y/%m/%d"))
        
        query = start_date_query
        if last_updated:
            if last_updated.tzinfo is None:
                last_updated = last_updated.replace(tzinfo=timezone.utc)
            additional_time = last_updated.strftime("%Y/%m/%d")
            query = f"{QUERY_APPLIED_EMAIL_FILTER} after:{additional_time}"
            logger.info(f"user_id:{user_id} Fetching emails after {additional_time}")
        else:
            logger.info(f"user_id:{user_id} Fetching all emails starting from: {effective_start.date()}")

        # 5. Retrieve email message IDs from Gmail API
        messages = get_email_ids(query=query, gmail_instance=user_auth.service, user_id=user_id)
        
        if not messages:
            logger.info(f"user_id:{user_id} No new emails found.")
            process_task_run.status = task_models.FINISHED
            process_task_run.total_emails = 0
            process_task_run.processed_emails = 0
            db_session.add(process_task_run)
            db_session.commit()
            return

        logger.info(f"user_id:{user_id} Found {len(messages)} total emails to process.")
        process_task_run.total_emails = len(messages)
        db_session.commit()

        # 6. Process the batch (capped at 100 for safety or remaining tier quota)
        batch_limit = policy.get_batch_limit()
        process_task_run.total_emails = len(messages)
        email_records = []
        processed_this_run = 0

        for idx, message in enumerate(messages):
            processed_this_run = idx + 1
            if processed_this_run > batch_limit:
                # Loop break triggered by safety limit or tier quota
                processed_this_run -= 1 # Adjust to count actually completed
                logger.info(f"user_id:{user_id} Batch limit reached at {processed_this_run}. Stopping.")
                break
                
            msg_id = message["id"]
            logger.info(f"user_id:{user_id} Processing email {processed_this_run} of {len(messages)}")
            
            # Fetch full email content
            msg = get_email(message_id=msg_id, gmail_instance=user_auth.service, user_email=user_auth.user_email)
            
            if msg:
                try:
                    # Process with LLM (Gemini)
                    result = process_email(msg["text_content"], user_id, db_session)
                    
                    if result and result.get("job_application_status", "").lower() != "false positive":
                        message_data = {
                            "id": msg_id,
                            "company_name": result.get("company_name", "unknown"),
                            "application_status": result.get("job_application_status", "unknown"),
                            "received_at": msg.get("date", "unknown"),
                            "subject": decode_subject_line(msg.get("subject", "unknown")),
                            "job_title": result.get("job_title", "unknown"),
                            "from": msg.get("from", "unknown"),
                        }
                        email_record = create_user_email(user_id, message_data, db_session)
                        if email_record:
                            email_records.append(email_record)
                except Exception as e:
                    logger.error(f"Error processing message {msg_id}: {e}")

            # Update progress in the database after each email
            process_task_run.processed_emails = processed_this_run
            process_task_run.applications_found = len(email_records)
            db_session.add(process_task_run)
            db_session.commit()

        # 7. Finalize database state for this batch
        if email_records:
            db_session.add_all(email_records)
            db_session.commit()

        process_task_run.status = task_models.FINISHED
        db_session.commit()

        # 8. CHAINING LOGIC: Recursive sync for premium users to clear backlog
        if background_tasks and policy.should_chain(processed_this_run, len(messages)):
            logger.info(f"Premium chaining: Starting next batch for user {user_id}")
            # Incremental fetch point based on the most recently saved email
            new_last_updated = get_last_email_date(user_id, db_session)
            background_tasks.add_task(
                fetch_emails_to_db, 
                user_auth, 
                request, 
                new_last_updated, 
                user_id=user_id
            )
