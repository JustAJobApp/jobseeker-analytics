import csv
import email.utils as email_utils
import os
import logging
from fastapi import APIRouter, HTTPException, Request, Depends
from fastapi.responses import FileResponse, RedirectResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
import database
from utils.file_utils import get_user_filepath
from session.session_layer import validate_session, user_has_recent_authentication
from sqlmodel import select, desc
from db.user_emails import UserEmails
from utils.config_utils import get_settings
from utils.validator_utils import sanitize_csv_field

settings = get_settings()

# Logger setup
logger = logging.getLogger(__name__)

# FastAPI router for file routes
router = APIRouter()
limiter = Limiter(key_func=get_remote_address)


@router.get("/process-csv")
@limiter.limit("2/minute")
async def process_csv(
    request: Request,
    db_session: database.DBSession,
    user_id: str = Depends(validate_session),
):
    if not user_id:
        return RedirectResponse("/logout", status_code=303)

    if not user_has_recent_authentication(request):
        logger.info(f"Step-Up Auth required for user {user_id} attempting to download CSV.")
        raise HTTPException(status_code=403, detail="Step-Up Auth required", headers={"X-Step-Up-Auth": "true"})

    directory = get_user_filepath(user_id)
    filename = "emails.csv"
    filepath = os.path.join(directory, filename)

    # Fetch ALL processed emails — CSV is full data export regardless of tier
    emails = db_session.exec(
        select(UserEmails)
        .where(UserEmails.user_id == user_id)
        .order_by(desc(UserEmails.received_at))
    ).all()
    if not emails:
        raise HTTPException(status_code=400, detail="No data found to write")
    # Ensure the directory exists
    os.makedirs(directory, exist_ok=True)

    # CSV columns per spec: Date Received, Sender Name, Sender Email, Subject, Status Label
    headers = ["Date Received", "Sender Name", "Sender Email", "Subject", "Status Label"]

    def build_row(email_obj):
        sender_name, sender_email = email_utils.parseaddr(email_obj.email_from or "")
        received = email_obj.received_at.strftime("%Y-%m-%d") if email_obj.received_at else ""
        return [
            sanitize_csv_field(received),
            sanitize_csv_field(sender_name),
            sanitize_csv_field(sender_email or email_obj.email_from or ""),
            sanitize_csv_field(email_obj.subject or ""),
            sanitize_csv_field(email_obj.application_status or "")
        ]

    # Write to CSV
    with open(filepath, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        for email_obj in emails:
            writer.writerow(build_row(email_obj))

    logger.info("CSV file created at %s", filepath)

    # Download CSV
    if os.path.exists(filepath):
        logger.info("user_id:%s downloading from filepath %s", user_id, filepath)
        return FileResponse(filepath)

    # File not found error
    raise HTTPException(status_code=400, detail="File not found")
