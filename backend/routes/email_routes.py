import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, Request, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlmodel import select, desc
from db.user_emails import UserEmails
from db import processing_tasks as task_models
from db.utils.user_email_utils import create_user_email
from db.utils.user_utils import get_last_email_date
from utils.auth_utils import AuthenticatedUser
from utils.email_utils import get_email_ids, get_email, decode_subject_line
from utils.llm_utils import process_email
from utils.task_utils import exceeds_rate_limit
from utils.config_utils import get_settings
from session.session_layer import validate_session
import database
from google.oauth2.credentials import Credentials
import json
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


@router.get("/processing")
async def processing(
    request: Request,
    db_session: database.DBSession,
    user_id: str = Depends(validate_session),
):
    logging.info("user_id:%s processing", user_id)
    if not user_id:
        logger.info("user_id: not found, redirecting to login")
        return RedirectResponse("/logout", status_code=303)

    process_task_run: task_models.TaskRuns = db_session.get(
        task_models.TaskRuns, user_id
    )

    if not process_task_run:
        raise HTTPException(status_code=404, detail="Processing has not started.")

    # Refresh the session to ensure we get the latest data
    db_session.refresh(process_task_run)

    if process_task_run.status == task_models.FINISHED:
        logger.info("user_id: %s processing complete", user_id)
        return JSONResponse(
            content={
                "message": "Processing complete",
                "processed_emails": process_task_run.processed_emails,
                "total_emails": process_task_run.total_emails,
            }
        )
    else:
        logger.info(
            "user_id: %s processing not complete - processed: %s, total: %s, status: %s",
            user_id,
            process_task_run.processed_emails,
            process_task_run.total_emails,
            process_task_run.status,
        )
        return JSONResponse(
            content={
                "message": "Processing in progress",
                "processed_emails": process_task_run.processed_emails,
                "total_emails": process_task_run.total_emails,
            }
        )


@router.get("/get-emails", response_model=List[UserEmails])
@limiter.limit("5/minute")
def query_emails(request: Request, db_session: database.DBSession, user_id: str = Depends(validate_session)) -> None:
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
async def delete_email(request: Request, db_session: database.DBSession, email_id: str, user_id: str = Depends(validate_session)):
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

    except Exception as e:
        logger.error(f"Error deleting email with id {email_id} for user_id {user_id}: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to delete email: {str(e)}"
        )
        

@router.post("/fetch-emails")
@limiter.limit("5/minute")
async def start_fetch_emails(
    request: Request, background_tasks: BackgroundTasks, db_session: database.DBSession, user_id: str = Depends(validate_session)
):
    """Starts the background task for fetching and processing emails."""
    
    if not user_id:
        raise HTTPException(status_code=403, detail="Unauthorized")
    logger.info(f"user_id:{user_id} start_fetch_emails")
    # Retrieve stored credentials
    creds_json = request.session.get("creds")
    if not creds_json:
        logger.error(f"Missing credentials for user_id: {user_id}")
        return HTMLResponse(content="User not authenticated. Please log in again.", status_code=401)

    try:
        # Convert JSON string back to Credentials object
        creds_dict = json.loads(creds_json)
        creds = Credentials.from_authorized_user_info(creds_dict)  # Convert dict to Credentials
        user = AuthenticatedUser(creds)

        logger.info(f"Starting email fetching process for user_id: {user_id}")

        # Get the last email date for incremental fetching
        last_updated = get_last_email_date(user_id, db_session)

        # Start email fetching in the background
        background_tasks.add_task(fetch_emails_to_db, user, request, last_updated, user_id=user_id, db_session=db_session)

        return JSONResponse(content={"message": "Email fetching started"}, status_code=200)
    except Exception as e:
        logger.error(f"Error reconstructing credentials: {e}")
        raise HTTPException(status_code=500, detail="Failed to authenticate user")


def fetch_emails_to_db(
    user: AuthenticatedUser,
    request: Request,
    last_updated: Optional[datetime] = None,
    *,
    user_id: str,
    db_session,
) -> None:
    logger.info(f"Fetching emails to db for user_id: {user_id}")
    gmail_instance = user.service

    # we track starting and finishing fetching of emails for each user
    db_session.commit()  # Commit pending changes to ensure the database is in latest state
    process_task_run = db_session.exec(
        select(task_models.TaskRuns).filter_by(user_id=user_id)
    ).one_or_none()
    if process_task_run is None:
        # if this is the first time running the task for the user, create a record
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
    is_new_user = request.session.get("is_new_user")

    query = start_date_query
    # check for users last updated email
    if last_updated:
        # this converts our date time to number of seconds 
        additional_time = last_updated.strftime("%Y/%m/%d")
        # we append it to query so we get only emails recieved after however many seconds
        # for example, if the newest email you’ve stored was received at 2025‑03‑20 14:32 UTC, we convert that to 1710901920s 
        # and tell Gmail to fetch only messages received after March 20, 2025 at 14:32 UTC.
        if not start_date or not is_new_user:
            query = QUERY_APPLIED_EMAIL_FILTER
            query += f" after:{additional_time}"
            logger.info(f"user_id:{user_id} Fetching emails after {additional_time}")
    else:
        logger.info(f"user_id:{user_id} Fetching all emails (no last_date maybe with start date)")


    messages = get_email_ids(query=query, gmail_instance=gmail_instance, user_id=user_id)
    # Update session to remove "new user" status
    request.session["is_new_user"] = False

    if not messages:
        logger.info(f"user_id:{user_id} No job application emails found.")
        process_task_run = db_session.get(task_models.TaskRuns, user_id)
        process_task_run.status = task_models.FINISHED
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

        logger.debug(f"user_id:{user_id} getting email content for message {idx + 1}")
        msg = get_email(
            message_id=msg_id,
            gmail_instance=gmail_instance,
            user_email=user.user_email,
        )

        if msg:
            logger.debug(f"user_id:{user_id} email content retrieved for message {idx + 1}, processing with LLM")
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
            email_record = create_user_email(user, message_data, db_session)
            
            if email_record:
                email_records.append(email_record)
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
