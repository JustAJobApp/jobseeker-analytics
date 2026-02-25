import csv
import os
import logging
from fastapi import APIRouter, HTTPException, Request, Depends
from fastapi.responses import FileResponse, RedirectResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
import database
from utils.file_utils import get_user_filepath
from session.session_layer import validate_session, user_has_recent_authentication
from routes.email_routes import query_emails
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

    # Get job related email data from DB
    emails = query_emails(request, db_session=db_session, user_id=user_id)
    if not emails:
        raise HTTPException(status_code=400, detail="No data found to write")
    # Ensure the directory exists
    os.makedirs(directory, exist_ok=True)

    # Key: DB field name; Value: Human-readable field name
    field_mapping = {
        "company_name": "Company Name",
        "application_status": "Application Status",
        "received_at": "Received At",
        "job_title": "Job Title",
        "subject": "Subject",
        "email_from": "Sender",
    }

    if not settings.is_publicly_deployed:
        field_mapping.update({"id": "Message ID"})

    selected_fields = list(field_mapping.keys())
    headers = list(field_mapping.values())

    # Filter out unwanted fields
    processed_emails = [
        {key: value for key, value in email if key in selected_fields}
        for email in emails
    ]

    # Write to CSV
    with open(filepath, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        for row in processed_emails:
            writer.writerow([sanitize_csv_field(row.get(field, "")) for field in selected_fields])

    logger.info("CSV file created at %s", filepath)

    # Download CSV
    if os.path.exists(filepath):
        logger.info("user_id:%s downloading from filepath %s", user_id, filepath)
        return FileResponse(filepath)

    # File not found error
    raise HTTPException(status_code=400, detail="File not found")
