import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, Request, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from sqlmodel import select, desc
from db.user_emails import UserEmails
from db import processing_tasks as task_models
from db.users import Users
from db.utils.user_email_utils import create_user_email, check_email_exists
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
from datetime import datetime, timezone, timedelta
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.util import get_remote_address
from utils.job_utils import normalize_job_title
from utils.billing_utils import is_premium_eligible
from utils.tier_limits import FREE_HISTORY_DAYS

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
        # Rescan if quick scan didn't finish full history, or if >24h since last scan
        if not last_finished_task.history_sync_completed:
            should_rescan = True
        else:
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

    # Get scan date range from the current/latest task
    scan_start_date = None
    scan_end_date = None
    if process_task_run.scan_start_date:
        scan_start = process_task_run.scan_start_date
        if scan_start.tzinfo is None:
            scan_start = scan_start.replace(tzinfo=timezone.utc)
        scan_start_date = scan_start.isoformat()
    if process_task_run.scan_end_date:
        scan_end = process_task_run.scan_end_date
        if scan_end.tzinfo is None:
            scan_end = scan_end.replace(tzinfo=timezone.utc)
        scan_end_date = scan_end.isoformat()

    return {
        "status": status,
        "total_emails": process_task_run.total_emails or 0,
        "processed_emails": process_task_run.processed_emails or 0,
        "applications_found": applications_found,
        "last_scan_at": last_scan_at,
        "should_rescan": should_rescan,
        "scan_start_date": scan_start_date,
        "scan_end_date": scan_end_date,
        "stop_reason": process_task_run.stop_reason,
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

        # If history sync is incomplete (quick scan), do a full scan from start_date.
        # Otherwise do an incremental scan from the last processed email date.
        last_finished = db_session.exec(
            select(task_models.TaskRuns)
            .where(task_models.TaskRuns.user_id == user_id)
            .where(task_models.TaskRuns.status == task_models.FINISHED)
            .order_by(task_models.TaskRuns.updated.desc())
        ).first()
        if last_finished and not last_finished.history_sync_completed:
            last_updated = None  # full re-scan from start_date
        elif last_finished and last_finished.last_processed_date:
            # Use last_processed_date to avoid rescanning false positives
            last_updated = last_finished.last_processed_date
        else:
            # Fallback for old tasks without last_processed_date
            last_updated = get_last_email_date(user_id, db_session)

        # Create TaskRun record BEFORE starting background task to avoid race condition
        # where frontend fetches /processing/status before TaskRun exists
        process_task_run = task_models.TaskRuns(user_id=user_id, status=task_models.STARTED)
        db_session.add(process_task_run)
        db_session.commit()
        db_session.refresh(process_task_run)
        task_run_id = process_task_run.id

        start_date = request.session.get("start_date")
        start_date_updated = request.session.get("start_date_updated")
        gmail_query = build_gmail_query(last_updated, start_date_updated, start_date, user.scan_end_date)

        background_tasks.add_task(fetch_emails_to_db, auth_user, request, last_updated, user_id=user_id, gmail_query=gmail_query, task_run_id=task_run_id)

        logger.info(f"Manual scan started for user {user_id}")
        return {"message": "Processing started", "gmail_query": gmail_query}
    except HTTPException:
        # Re-raise HTTP exceptions (like gmail_scope_missing) as-is
        raise
    except Exception as e:
        logger.error(f"Error starting scan for user {user_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to start processing")


@router.post("/processing/cancel")
@limiter.limit("10/minute")
async def cancel_processing(
    request: Request,
    db_session: database.DBSession,
    user_id: str = Depends(validate_session),
):
    """Cancel an in-progress email scan.

    Returns 404 if no scan is in progress.
    Returns 200 if scan was cancelled successfully.
    """
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    active_task = db_session.exec(
        select(task_models.TaskRuns)
        .where(task_models.TaskRuns.user_id == user_id)
        .where(task_models.TaskRuns.status == task_models.STARTED)
    ).first()

    if not active_task:
        raise HTTPException(
            status_code=404,
            detail="no_active_scan"
        )

    active_task.status = task_models.CANCELLED
    active_task.stop_reason = task_models.STOP_REASON_USER_CANCELLED
    db_session.commit()

    logger.info(f"Scan cancelled by user {user_id}")
    return {"message": "Scan cancelled"}


class EmailPreviewItem(BaseModel):
    sender: str
    sender_domain: str
    subject: str
    date: str


class EmailPreviewResponse(BaseModel):
    emails: list[EmailPreviewItem]
    total_count: int
    limited: bool
    gmail_query: str


def get_email_metadata(message_id: str, gmail_instance):
    """Fetch only email metadata (headers) without the body content."""
    try:
        message = (
            gmail_instance.users()
            .messages()
            .get(userId="me", id=message_id, format="metadata", metadataHeaders=["From", "Subject", "Date"])
            .execute()
        )

        headers = message.get("payload", {}).get("headers", [])
        metadata = {"id": message_id}

        for header in headers:
            name = header.get("name", "").lower()
            value = header.get("value", "")
            if name == "from":
                metadata["from"] = value
            elif name == "subject":
                metadata["subject"] = decode_subject_line(value)
            elif name == "date":
                metadata["date"] = value

        return metadata
    except Exception as e:
        logger.error(f"Error fetching metadata for email {message_id}: {e}")
        return None


def extract_sender_domain(from_header: str) -> str:
    """Extract the domain from an email From header."""
    import re
    # Match email in angle brackets or bare email
    match = re.search(r'<([^>]+)>|([^\s<>]+@[^\s<>]+)', from_header)
    if match:
        email = match.group(1) or match.group(2)
        if "@" in email:
            return email.split("@")[1].lower()
    return ""


def extract_sender_name(from_header: str) -> str:
    """Extract the sender name from an email From header."""
    # If there's a name before the email in brackets
    if "<" in from_header:
        name = from_header.split("<")[0].strip()
        # Remove quotes if present
        name = name.strip('"').strip("'")
        if name:
            return name
    # Fallback to the email address
    return from_header


@router.get("/api/emails/preview", response_model=EmailPreviewResponse)
@limiter.limit("10/minute")
async def preview_emails(
    request: Request,
    db_session: database.DBSession,
    start_date: str,
    end_date: str = None,
    user_id: str = Depends(validate_session),
):
    """Preview matching emails before processing.

    Returns email metadata (sender, subject, date) without processing.
    Does NOT consume monthly cap. Does NOT run smart tags.

    Free users see up to 25 emails. Paid users see all.
    """
    from utils.filter_utils import parse_base_filter_config
    from pathlib import Path

    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = db_session.exec(select(Users).where(Users.user_id == user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Load credentials
    try:
        creds = get_credentials_for_background_task(db_session, user_id)
        if not creds:
            raise HTTPException(status_code=401, detail="token_expired")

        gmail_scope = "https://www.googleapis.com/auth/gmail.readonly"
        if not creds.scopes or gmail_scope not in creds.scopes:
            raise HTTPException(status_code=403, detail="gmail_scope_missing")

        auth_user = AuthenticatedUser(
            creds,
            _user_id=user.user_id,
            _user_email=user.user_email
        )
        gmail_instance = auth_user.service
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error loading credentials for preview: {e}")
        raise HTTPException(status_code=500, detail="Failed to load credentials")

    # Build query with date range
    filter_path = Path(__file__).parent.parent / "email_query_filters" / "applied_email_filter.yaml"
    base_filter = parse_base_filter_config(filter_path)

    query = f"after:{start_date} -from:me -in:sent AND ({base_filter})"
    if end_date:
        query = f"after:{start_date} before:{end_date} -from:me -in:sent AND ({base_filter})"

    logger.info(f"Preview query for user {user_id}: {query}")

    # Fetch email IDs
    try:
        messages = get_email_ids(query=query, gmail_instance=gmail_instance, user_id=user_id)
    except Exception as e:
        logger.error(f"Error fetching email IDs for preview: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch emails from Gmail")

    total_count = len(messages)

    # Always limit preview to 15 emails - enough to build trust without excessive scrolling
    # Gmail returns newest first, so reverse to get oldest first
    preview_limit = 15
    limited = total_count > preview_limit
    messages = list(reversed(messages))  # oldest first

    if len(messages) > preview_limit:
        messages = messages[:preview_limit]

    # Fetch metadata for each email (unique senders only)
    preview_emails = []
    seen_senders = set()
    for msg in messages:
        metadata = get_email_metadata(msg["id"], gmail_instance)
        if metadata:
            from_header = metadata.get("from", "")
            sender_domain = extract_sender_domain(from_header)
            # Skip if we've already seen this sender
            if sender_domain in seen_senders:
                continue
            seen_senders.add(sender_domain)
            preview_emails.append(EmailPreviewItem(
                sender=extract_sender_name(from_header),
                sender_domain=sender_domain,
                subject=metadata.get("subject", "(No subject)"),
                date=metadata.get("date", "")
            ))

    # Sort by date (oldest first to match processing order)
    def parse_email_date(date_str: str) -> datetime:
        from email.utils import parsedate_to_datetime
        try:
            return parsedate_to_datetime(date_str)
        except Exception:
            return datetime.min.replace(tzinfo=timezone.utc)

    preview_emails.sort(key=lambda e: parse_email_date(e.date), reverse=False)

    return EmailPreviewResponse(
        emails=preview_emails,
        total_count=total_count,
        limited=limited,
        gmail_query=query,
    )


@router.get("/emails/hidden-count")
@limiter.limit("20/minute")
def emails_hidden_count(request: Request, db_session: database.DBSession, user_id: str = Depends(get_context_user_id)):
    """Return the count of emails hidden from free-tier users.

    Free users see only the last 30 days through today.
    Returns hidden_count=0 and cutoff_date=None for premium users.
    """
    from sqlmodel import func

    user = db_session.exec(select(Users).where(Users.user_id == user_id)).first()
    if not user or is_premium_eligible(db_session, user):
        return {"hidden_count": 0, "cutoff_date": None}

    # Free users: visible window is (today - 30 days) to today
    cutoff_dt = datetime.now(timezone.utc) - timedelta(days=FREE_HISTORY_DAYS)

    # Count emails BEFORE the cutoff (these are hidden from free users)
    hidden_count = db_session.exec(
        select(func.count(UserEmails.id)).where(
            UserEmails.user_id == user_id,
            UserEmails.received_at < cutoff_dt,
            ~UserEmails.id.like("manual_%"),
        )
    ).one()

    return {"hidden_count": hidden_count, "cutoff_date": cutoff_dt.isoformat()}


@router.get("/get-emails/preview")
@limiter.limit("10/minute")
def get_emails_preview(request: Request, db_session: database.DBSession, user_id: str = Depends(validate_session)):
    """Get a preview of emails (up to 4 unique companies) - works during onboarding before completion."""
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    statement = select(UserEmails).where(UserEmails.user_id == user_id).order_by(desc(UserEmails.received_at))
    emails = db_session.exec(statement).all()

    # Return unique companies only (up to 4)
    seen_companies = set()
    unique_emails = []
    for e in emails:
        if e.company_name not in seen_companies:
            seen_companies.add(e.company_name)
            unique_emails.append({"company_name": e.company_name, "application_status": e.application_status})
            if len(unique_emails) >= 4:
                break

    return {"emails": unique_emails}


@router.get("/get-emails", response_model=List[UserEmails])
@limiter.limit("5/minute")
def query_emails(request: Request, db_session: database.DBSession, user_id: str = Depends(get_context_user_id)) -> None:
    try:
        logger.info(f"query_emails for user_id: {user_id}")
        # Query emails sorted by date (newest first)
        db_session.expire_all()  # Clear any cached data
        db_session.commit()  # Commit pending changes to ensure the database is in latest state
        statement = select(UserEmails).where(UserEmails.user_id == user_id)

        # Free-tier users see only the last 30 days through today
        user = db_session.exec(select(Users).where(Users.user_id == user_id)).first()
        if user and not is_premium_eligible(db_session, user):
            from sqlmodel import or_
            cutoff_dt = datetime.now(timezone.utc) - timedelta(days=FREE_HISTORY_DAYS)
            statement = statement.where(
                or_(
                    UserEmails.id.like("manual_%"),
                    UserEmails.received_at >= cutoff_dt,
                )
            )

        statement = statement.order_by(desc(UserEmails.received_at))
        user_emails = db_session.exec(statement).all()

        for email in user_emails:

            if email.job_title is None or email.job_title == "" or email.job_title == "null":
                new_job_title = 'Unknown'
            else:
                new_job_title = normalize_job_title(email.job_title) or 'Unknown'
            if email.job_title != new_job_title:
                email.job_title = new_job_title
                db_session.add(email)
                db_session.commit()
                logger.info(f"Updated job title for email {email.id} to {new_job_title}")

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
        

def build_gmail_query(
    last_updated: Optional[datetime],
    start_date_updated: bool,
    start_date: Optional[str],
    scan_end_date: Optional[datetime],
) -> str:
    is_incremental = last_updated and not start_date_updated
    if is_incremental:
        query = QUERY_APPLIED_EMAIL_FILTER + f" after:{last_updated.strftime('%Y/%m/%d')}"
    else:
        query = get_start_date_email_filter(start_date)
    if scan_end_date:
        query += f" before:{scan_end_date.strftime('%Y/%m/%d')}"
    return query


def fetch_emails_to_db(
    user: AuthenticatedUser,
    request: Request,
    last_updated: Optional[datetime] = None,
    *,
    user_id: str,
    gmail_query: str,
    quick_limit: Optional[int] = None,
    task_run_id: Optional[int] = None,
) -> None:
    logger.info(f"fetch_emails_to_db for user_id: {user_id}")
    try:
        _fetch_emails_to_db_impl(user, request, last_updated, user_id=user_id, gmail_query=gmail_query, quick_limit=quick_limit, task_run_id=task_run_id)
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
                    process_task_run.stop_reason = task_models.STOP_REASON_ERROR
                    db_session.commit()
                    logger.info(f"Marked task as CANCELLED (error) for user_id {user_id}")
        except Exception as cleanup_error:
            logger.error(f"Error cleaning up task for user_id {user_id}: {cleanup_error}")


def _fetch_emails_to_db_impl(
    user: AuthenticatedUser,
    request: Request,
    last_updated: Optional[datetime] = None,
    *,
    user_id: str,
    gmail_query: str,
    quick_limit: Optional[int] = None,
    task_run_id: Optional[int] = None,
) -> None:
    with database.get_session() as db_session:
        gmail_instance = user.service

        # we track starting and finishing fetching of emails for each user
        db_session.commit()  # Commit pending changes to ensure the database is in latest state

        # If task_run_id is provided, use the pre-created TaskRun (from manual refresh)
        # Otherwise check for active task and create new one (OAuth callback flow)
        if task_run_id:
            process_task_run = db_session.exec(
                select(task_models.TaskRuns).where(task_models.TaskRuns.id == task_run_id)
            ).first()
            if not process_task_run:
                logger.error(f"TaskRun {task_run_id} not found for user_id {user_id}")
                return
        else:
            # Check for an active (STARTED) task to prevent concurrent scans
            active_task: task_models.TaskRuns = db_session.exec(
                select(task_models.TaskRuns).where(
                    task_models.TaskRuns.user_id == user_id,
                    task_models.TaskRuns.status == task_models.STARTED
                )
            ).first()

            if active_task:
                logger.warning(
                    "User already has an active scan in progress",
                    extra={"user_id": user_id, "task_id": active_task.id},
                )
                return JSONResponse(content={"message": "Scan already in progress"}, status_code=409)

            # Always create a new TaskRun record for each scan (maintains scan history)
            process_task_run = task_models.TaskRuns(user_id=user_id, status=task_models.STARTED)
            db_session.add(process_task_run)
            db_session.commit()

        start_date = request.session.get("start_date")
        existing_user = db_session.exec(
            select(Users).where(Users.user_id == user_id)
        ).first()

        # Fall back to user's configured start_date if session doesn't have one
        start_date_updated = False
        if existing_user and existing_user.start_date:
            user_start_date = existing_user.start_date.strftime('%Y/%m/%d')
            if not start_date:
                # Apply free tier limit: cap at 30 days ago for non-premium users
                if not is_premium_eligible(db_session, existing_user):
                    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=FREE_HISTORY_DAYS)
                    user_start = existing_user.start_date
                    # Ensure timezone-aware comparison
                    if user_start.tzinfo is None:
                        user_start = user_start.replace(tzinfo=timezone.utc)
                    effective_start = max(user_start, thirty_days_ago)
                    start_date = effective_start.strftime('%Y/%m/%d')
                    logger.info(f"user_id:{user_id} Free tier: capping start_date to {start_date} (was {user_start_date})")
                else:
                    start_date = user_start_date
                    logger.info(f"Using user's configured start_date: {start_date}")
            elif start_date != user_start_date:
                logger.info(f"start_date {start_date} != user.start_date {user_start_date}")
                start_date_updated = True

        logger.info(f"start_date: {start_date}")
        start_date_query = get_start_date_email_filter(start_date)

        # Monthly cap enforcement
        from utils.billing_utils import get_monthly_email_cap, reset_monthly_counter_if_needed

        if existing_user:
            existing_user = reset_monthly_counter_if_needed(existing_user)
            db_session.add(existing_user)
            db_session.commit()

            monthly_cap = get_monthly_email_cap(db_session, existing_user)
            emails_remaining = monthly_cap - (existing_user.emails_processed_this_month or 0)

            if emails_remaining <= 0:
                logger.info(f"user_id:{user_id} Monthly email cap reached ({monthly_cap}), cancelling scan")
                process_task_run.status = task_models.CANCELLED
                process_task_run.stop_reason = task_models.STOP_REASON_MONTHLY_CAP
                db_session.commit()
                return
        else:
            monthly_cap = None
            emails_remaining = None

        is_incremental_scan = last_updated and not start_date_updated

        # Store scan date range on the task run for historical tracking
        # For incremental scans, use last_updated as start; for full scans, use start_date
        if is_incremental_scan:
            process_task_run.scan_start_date = last_updated
        elif start_date:
            try:
                parsed = datetime.strptime(start_date, "%Y/%m/%d")
                process_task_run.scan_start_date = parsed.replace(tzinfo=timezone.utc)
            except ValueError:
                logger.warning(f"Could not parse start_date: {start_date}")
        if existing_user and existing_user.scan_end_date:
            process_task_run.scan_end_date = existing_user.scan_end_date
        else:
            process_task_run.scan_end_date = datetime.now(timezone.utc)
        db_session.commit()

        query = gmail_query
        if is_incremental_scan:
            logger.info(f"user_id:{user_id} Fetching emails after {last_updated.strftime('%Y/%m/%d')} (incremental scan)")
        else:
            logger.info(f"user_id:{user_id} Fetching all emails with start date: {start_date} (full scan)")

        messages = get_email_ids(query=query, gmail_instance=gmail_instance, user_id=user_id)

        # Reverse for oldest-first processing
        if existing_user and existing_user.fetch_order == "oldest_first":
            messages = list(reversed(messages))

        # Apply monthly cap slice AFTER ordering
        if emails_remaining is not None and len(messages) > emails_remaining:
            logger.info(f"user_id:{user_id} Limiting scan to {emails_remaining} emails (monthly cap)")
            messages = messages[:emails_remaining]

        # Apply quick_limit for onboarding fast-path
        is_quick_scan = False
        if quick_limit is not None and len(messages) > quick_limit:
            logger.info(f"user_id:{user_id} Quick scan: limiting to {quick_limit} of {len(messages)} emails")
            messages = messages[:quick_limit]
            is_quick_scan = True

        # Update session to remove "new user" status
        request.session["is_new_user"] = False

        if not messages:
            logger.info(f"user_id:{user_id} No job application emails found (is_incremental={is_incremental_scan}).")
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
                # For full scans with no messages, mark history complete
                # For incremental scans, preserve the previous history_sync_completed value
                if is_incremental_scan:
                    # Exclude current task (status was just set to FINISHED but not committed)
                    last_finished = db_session.exec(
                        select(task_models.TaskRuns)
                        .where(task_models.TaskRuns.user_id == user_id)
                        .where(task_models.TaskRuns.status == task_models.FINISHED)
                        .where(task_models.TaskRuns.id != process_task_run.id)
                        .order_by(task_models.TaskRuns.updated.desc())
                    ).first()
                    if last_finished:
                        process_task_run.history_sync_completed = last_finished.history_sync_completed
                    # else: stays False, will trigger full scan next time
                else:
                    process_task_run.history_sync_completed = True
                db_session.add(process_task_run)
                db_session.commit()
            return

        logger.info(f"user_id:{user.user_id} Found {len(messages)} emails.")
        process_task_run.total_emails = len(messages)
        db_session.commit()

        email_records = []  # list to collect email records
        latest_processed_date: Optional[datetime] = None  # Track latest email date scanned

        for idx, message in enumerate(messages):
            # Check for cancellation every 5 emails to balance responsiveness with DB load
            if idx % 5 == 0:
                db_session.expire(process_task_run)
                current_task = db_session.exec(
                    select(task_models.TaskRuns).where(
                        task_models.TaskRuns.id == process_task_run.id
                    )
                ).first()
                if current_task and current_task.status == task_models.CANCELLED:
                    logger.info(f"user_id:{user_id} Scan cancelled by user at email {idx}")
                    return

            message_data = {}
            # (email_subject, email_from, email_domain, company_name, email_dt)
            msg_id = message["id"]
            if check_email_exists(user_id, msg_id, db_session):
                logger.debug(f"user_id:{user_id} skipping already-processed email {msg_id}")
                continue
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
                # Track latest email date scanned (for incremental scan accuracy)
                email_date_str = msg.get("date")
                if email_date_str:
                    try:
                        from email.utils import parsedate_to_datetime
                        email_date = parsedate_to_datetime(email_date_str)
                        if latest_processed_date is None or email_date > latest_processed_date:
                            latest_processed_date = email_date
                    except Exception:
                        pass  # Skip if date parsing fails
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
                    # Stop quick scan after 25 applications found (aha moment)
                    if is_quick_scan and len(email_records) >= 25:
                        logger.info(f"user_id:{user_id} Quick scan reached 25 applications, stopping for aha moment")
                        break
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

        # Increment monthly counter
        if existing_user:
            existing_user = db_session.exec(
                select(Users).where(Users.user_id == user_id)
            ).first()
            if existing_user:
                existing_user.emails_processed_this_month = (
                    existing_user.emails_processed_this_month or 0
                ) + len(email_records)
                db_session.add(existing_user)
                db_session.commit()

        process_task_run.status = task_models.FINISHED
        # For quick scans, always False (need full scan later)
        # For full scans, set True
        # For incremental scans, preserve previous history_sync_completed value
        if is_quick_scan:
            process_task_run.history_sync_completed = False
        elif is_incremental_scan:
            # Exclude current task (status was just set to FINISHED but not committed)
            last_finished = db_session.exec(
                select(task_models.TaskRuns)
                .where(task_models.TaskRuns.user_id == user_id)
                .where(task_models.TaskRuns.status == task_models.FINISHED)
                .where(task_models.TaskRuns.id != process_task_run.id)
                .order_by(task_models.TaskRuns.updated.desc())
            ).first()
            if last_finished:
                process_task_run.history_sync_completed = last_finished.history_sync_completed
            # else: stays False, will trigger full scan next time
        else:
            process_task_run.history_sync_completed = True

        # Save the latest email date scanned for accurate incremental scans
        if latest_processed_date:
            process_task_run.last_processed_date = latest_processed_date
        db_session.commit()

        logger.info(f"user_id:{user_id} Email fetching complete (is_quick={is_quick_scan}, is_incremental={is_incremental_scan}, history_sync_completed={process_task_run.history_sync_completed}, last_processed_date={process_task_run.last_processed_date}).")

    # If this was a quick scan (onboarding), start a follow-up scan to get the rest
    # This is outside the db_session context to ensure clean session management
    if is_quick_scan:
        logger.info(f"user_id:{user_id} Quick scan complete, starting follow-up scan for remaining emails")
        _fetch_emails_to_db_impl(user, request, last_updated, user_id=user_id, gmail_query=gmail_query, quick_limit=None)
