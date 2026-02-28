import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, Request, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from sqlmodel import select, desc
from db.user_emails import UserEmails
from db import processing_tasks as task_models
from db.users import Users
from db.utils.user_email_utils import create_user_email
from db.utils.user_utils import get_last_email_date
from utils.auth_utils import AuthenticatedUser
from utils.email_utils import get_email_ids, get_email, decode_subject_line
from utils.llm_utils import process_email
from utils.task_utils import exceeds_rate_limit
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
    user: AuthenticatedUser,
    request: Request,
    last_updated: Optional[datetime] = None,
    *,
    user_id: str,
) -> None:
    with database.get_session() as db_session:
        gmail_instance = user.service

        # we track starting and finishing fetching of emails for each user
        db_session.commit()  # Commit pending changes to ensure the database is in latest state
        process_task_run: task_models.TaskRuns = db_session.exec(
            select(task_models.TaskRuns).where(
                task_models.TaskRuns.user_id == user_id
            ).order_by(task_models.TaskRuns.updated.desc())
        ).first()
        if process_task_run is None:
            # if there are no STARTED tasks, create a new task record
            process_task_run = task_models.TaskRuns(user_id=user_id, status=task_models.STARTED)
            db_session.add(process_task_run)
            db_session.commit()
        else:
            # Check if the task was completed on a different day
            from datetime import datetime, timezone
            today = datetime.now(timezone.utc).date()
            task_date = process_task_run.updated.date() if process_task_run.updated else None
            
            # If the task was completed on a different day, reset the processed emails count
            if task_date and task_date < today:
                logger.info(f"Task was completed on {task_date}, resetting processed emails count for today")
                process_task_run.processed_emails = 0
                process_task_run.total_emails = 0
            elif process_task_run.processed_emails >= settings.batch_size_by_env:
                # limit how frequently emails can be fetched by a specific user (only if same day)
                logger.warning(
                    "Already fetched the maximum number (%s) of emails for this user for today",
                    settings.batch_size_by_env,
                    extra={"user_id": user_id},
                )
                process_task_run.status = task_models.CANCELLED
                db_session.commit()
                return JSONResponse(content={"message": "Processing complete"}, status_code=429)

        process_task_run.status = task_models.STARTED

        db_session.commit()  # sync with the database so calls in the future reflect the task is already started

        start_date = request.session.get("start_date")
        logger.info(f"start_date: {start_date}")
        start_date_query = get_start_date_email_filter(start_date)
        start_date_updated = False
        existing_user = db_session.exec(
            select(Users).where(Users.user_id == user_id)
        ).first()
        if existing_user and existing_user.start_date and start_date != existing_user.start_date.strftime('%Y/%m/%d'):
            logger.info(f"start_date {start_date} != user.start_date {existing_user.start_date.strftime('%Y/%m/%d')}")
            start_date_updated = True

        query = start_date_query
        # check for users last updated email
        if last_updated and not start_date_updated:
            # this converts our date time to number of seconds
            additional_time = last_updated.strftime("%Y/%m/%d")
            # we append it to query so we get only emails recieved after however many seconds
            # for example, if the newest email you’ve stored was received at 2025‑03‑20 14:32 UTC, we convert that to 1710901920s
            # and tell Gmail to fetch only messages received after March 20, 2025 at 14:32 UTC.
            query = QUERY_APPLIED_EMAIL_FILTER
            query += f" after:{additional_time}"
            logger.info(f"user_id:{user_id} Fetching emails after {additional_time}")
        else:
            logger.info(f"user_id:{user_id} Fetching all emails with start date: {start_date}")

        messages = get_email_ids(query=query, gmail_instance=gmail_instance, user_id=user_id)
        # Update session to remove "new user" status
        request.session["is_new_user"] = False

        if not messages:
            logger.info(f"user_id:{user_id} No job application emails found.")
            process_task_run: task_models.TaskRuns = db_session.exec(
                select(task_models.TaskRuns).where(
                    task_models.TaskRuns.user_id == user_id,
                    task_models.TaskRuns.status == task_models.STARTED
                )
            ).one_or_none()
            if process_task_run:
                process_task_run.status = task_models.FINISHED
                process_task_run.total_emails = 0
                process_task_run.processed_emails = 0
                db_session.add(process_task_run)
                db_session.commit()
            return

        logger.info(f"user_id:{user.user_id} Found {len(messages)} emails.")
        process_task_run.total_emails = len(messages)
        db_session.commit()

        email_records = []  # list to collect email records

        for idx, message in enumerate(messages):
            message_data = {}
            # (email_subject, email_from, email_domain, company_name, email_dt)
            msg_id = message["id"]
            logger.info(
                f"user_id:{user_id} begin processing for email {idx + 1} of {len(messages)} with id {msg_id}"
            )
            process_task_run.processed_emails = idx + 1
            db_session.add(process_task_run)
            db_session.commit()

            logger.debug(f"user_id:{user_id} getting email content for message {idx + 1}")
            msg = get_email(
                message_id=msg_id,
                gmail_instance=gmail_instance,
                user_email=user.user_email,
            )

            if msg:
                logger.debug(f"user_id:{user_id} email content retrieved for message {idx + 1}, processing with LLM")
                result = None
                try:
                    result = process_email(msg["text_content"], user_id, db_session)
                    logger.debug(f"user_id:{user_id} LLM processing completed for message {idx + 1}")
                    
                    # if values are empty strings or null, set them to "unknown"
                    for key in result.keys():
                        if not result[key]:
                            result[key] = "unknown"
                            
                    logger.debug(f"user_id:{user_id} processed result for message {idx + 1}: {result}")
                except Exception as e:
                    logger.error(
                        f"user_id:{user_id} Error processing email {idx + 1} of {len(messages)} with id {msg_id}: {e}"
                    )

                if not isinstance(result, str) and result:
                    logger.info(
                        f"user_id:{user_id} successfully extracted email {idx + 1} of {len(messages)} with id {msg_id}"
                    )
                    if result.get("job_application_status").lower().strip() == "false positive":
                        logger.info(
                            f"user_id:{user_id} email {idx + 1} of {len(messages)} with id {msg_id} is a false positive, not related to job search"
                        )
                        continue  # skip this email if it's a false positive
                else:  # processing returned unknown which is also likely false positive
                    logger.warning(
                        f"user_id:{user_id} failed to extract email {idx + 1} of {len(messages)} with id {msg_id}"
                    )
                    result = {"company_name": "unknown", "application_status": "unknown", "job_title": "unknown"}

                logger.debug(f"user_id:{user_id} creating message data for email {idx + 1}")
                message_data = {
                    "id": msg_id,
                    "company_name": result.get("company_name", "unknown"),
                    "application_status": result.get("job_application_status", "unknown"),
                    "received_at": msg.get("date", "unknown"),
                    "subject": msg.get("subject", "unknown"),
                    "job_title": result.get("job_title", "unknown"),
                    "from": msg.get("from", "unknown"),
                }
                message_data["subject"] = decode_subject_line(message_data["subject"])
                
                logger.debug(f"user_id:{user_id} creating user email record for message {idx + 1}")
                email_record = create_user_email(user_id, message_data, db_session)
                
                if email_record:
                    email_records.append(email_record)
                    # Update applications_found count in task run
                    process_task_run.applications_found = len(email_records)
                    db_session.add(process_task_run)
                    db_session.commit()
                    # check rate limit against total daily count
                    if exceeds_rate_limit(process_task_run.processed_emails):
                        logger.warning(f"Rate limit exceeded for user {user_id} at {process_task_run.processed_emails} emails")
                        break
                    logger.debug(f"Added email record for {message_data.get('company_name', 'unknown')} - {message_data.get('application_status', 'unknown')}")
                else:
                    logger.debug(f"Skipped email record (already exists or error) for {message_data.get('company_name', 'unknown')}")
                    
                logger.debug(f"user_id:{user_id} completed processing email {idx + 1} of {len(messages)}")
            else:
                logger.warning(f"user_id:{user_id} failed to retrieve email content for message {idx + 1} with id {msg_id}")

            # Update the task status in the database after each email
            logger.debug(f"user_id:{user_id} updating task status after processing email {idx + 1}")

        # batch insert all records at once
        if email_records:
            logger.info(f"About to add {len(email_records)} email records to database for user {user_id}")
            db_session.add_all(email_records)
            db_session.commit()  # Commit immediately after adding records
            logger.info(
                f"Successfully committed {len(email_records)} email records for user {user_id}"
            )
        else:
            logger.warning(f"No email records to add for user {user_id}")

        process_task_run.status = task_models.FINISHED
        db_session.commit()

        logger.info(f"user_id:{user_id} Email fetching complete.")
