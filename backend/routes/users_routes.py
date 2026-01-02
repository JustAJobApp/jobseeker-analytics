import logging
from fastapi import APIRouter, Depends, Request, HTTPException
from sqlmodel import select
import database
from slowapi import Limiter
from slowapi.util import get_remote_address
from db.user_emails import UserEmails
from db.users import Users # Ensure this is imported
from utils.config_utils import get_settings
from session.session_layer import validate_session
from routes.email_routes import query_emails
from utils.job_utils import normalize_job_title

# Logger setup
logger = logging.getLogger(__name__)

# Get settings
settings = get_settings()
APP_URL = settings.APP_URL

api_call_finished = False

# FastAPI router for email routes
router = APIRouter()
limiter = Limiter(key_func=get_remote_address)


@router.post("/verify-beta-email")
@limiter.limit("10/hour")
async def verify_beta_email(request: Request, db_session: database.DBSession):
    data = await request.json()
    email = data.get("email")
    
    if not email:
        raise HTTPException(status_code=400, detail="Email is required")
        
    user = db_session.exec(select(Users).where(Users.user_email == email)).first()
    
    if user and user.is_active:
        return {"is_active": "True"}
    
    return {"is_active": "Truee"}


@router.get("/get-response-rate")   
@limiter.limit("2/minute")    
def response_rate_by_job_title(request: Request, db_session: database.DBSession, user_id: str = Depends(validate_session)):
    
    try:
        logger.info(f"Starting response rate calculation for user_id: {user_id}")
        
        # Get job related email data from DB
        user_emails = query_emails(request, db_session=db_session, user_id=user_id)
        logger.info(f"Retrieved {len(user_emails)} emails for user_id: {user_id}")

        # Create unique application IDs based on company_name only (ignore job_title for now)
        applications = {}
        
        for email in user_emails:
            if email.company_name:
                app_id = email.company_name  # Use only company name as unique identifier
                
                if app_id not in applications:
                    applications[app_id] = {
                        "company": email.company_name,
                        "job_title": email.job_title,
                        "normalized_job_title": getattr(email, 'normalized_job_title', ''),
                        "statuses": set()
                    }
                
                if email.application_status:
                    status = email.application_status.strip().lower()
                    # Ignore "unknown" statuses
                    if status != "unknown":
                        applications[app_id]["statuses"].add(status)

        logger.info(f"Created {len(applications)} unique applications for user_id: {user_id}")

        # Filter out applications that only have unknown statuses (no valid statuses)
        valid_applications = {}
        for app_id, app_data in applications.items():
            if app_data["statuses"]:  # Only include applications that have at least one valid status
                valid_applications[app_id] = app_data

        logger.info(f"Filtered to {len(valid_applications)} valid applications for user_id: {user_id}")

        # Group applications by normalized job title
        job_title_applications = {}
        
        for app_id, app_data in valid_applications.items():
            job_title = app_data["job_title"]
            normalized_job_title = app_data.get("normalized_job_title", "")
            
            # Skip applications with "unknown" job titles
            if job_title and job_title.lower() != "unknown":
                # Use normalized job title if available, otherwise normalize on-the-fly
                if normalized_job_title and normalized_job_title.strip():
                    display_title = normalized_job_title.title()  # Ensure capitalization
                    logger.debug(f"Using stored normalized title: '{job_title}' -> '{display_title}'")
                else:
                    # Fall back to on-the-fly normalization for backward compatibility
                    try:
                        logger.debug(f"Normalizing job title on-the-fly: '{job_title}'")
                        normalized_title = normalize_job_title(job_title)
                        # Only use normalized title if it's valid (not None or empty)
                        if normalized_title and normalized_title.strip():
                            display_title = normalized_title  # Already capitalized by normalize_job_title
                            logger.debug(f"On-the-fly normalization successful: '{job_title}' -> '{display_title}'")
                        else:
                            display_title = job_title.title()  # Fall back to capitalized original
                            logger.debug(f"Normalization returned empty, using capitalized original: '{job_title}' -> '{display_title}'")
                    except Exception as e:
                        logger.warning(f"Failed to normalize job title '{job_title}': {e}")
                        display_title = job_title.title()  # Fall back to capitalized original
                
                if display_title not in job_title_applications:
                    job_title_applications[display_title] = {
                        "total": 0,
                        "responses": 0
                    }
                
                job_title_applications[display_title]["total"] += 1
                
                # Check if this application received any response beyond initial confirmation/rejection
                statuses = app_data["statuses"]
                has_response = any(status not in ["application confirmation", "rejection"] for status in statuses)
                
                if has_response:
                    job_title_applications[display_title]["responses"] += 1

        logger.info(f"Grouped into {len(job_title_applications)} job title categories for user_id: {user_id}")

        # Calculate response rates for each job title
        response_rate = []
        for job_title, data in job_title_applications.items():
            rate = round((data["responses"] / data["total"]) * 100, 2)
            response_rate.append({
                "title": job_title,
                "rate": rate
            })
            logger.debug(f"Job title '{job_title}': {data['responses']}/{data['total']} = {rate}% response rate")

        logger.info(f"Calculated response rates for {len(response_rate)} job titles for user_id: {user_id}")
        return response_rate
    
    except Exception as e:
        logger.error(f"Error fetching job titles for user_id {user_id}: {e}")
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")

@router.get("/user-response-rate")
def calculate_response_rate(
    request: Request, db_session: database.DBSession, user_id: str = Depends(validate_session)
) -> dict:
    db_session.expire_all()  # Clear any cached data
    db_session.commit()  # Commit pending changes to ensure the database is in latest state
    user_emails = db_session.exec(
        select(UserEmails).where(UserEmails.user_id == user_id)
    ).all()

    # if user has no emails just return 0.0
    if not user_emails:
        return {"value": 0.0}

    # Create unique application IDs based on company_name only (ignore job_title for now)
    applications = {}
    
    for email in user_emails:
        if email.company_name:
            app_id = email.company_name  # Use only company name as unique identifier
            
            if app_id not in applications:
                applications[app_id] = {
                    "company": email.company_name,
                    "job_title": email.job_title,
                    "statuses": set(),
                    "received_at": email.received_at
                }
            
            if email.application_status:
                status = email.application_status.strip().lower()
                # Ignore "unknown" statuses
                if status != "unknown":
                    applications[app_id]["statuses"].add(status)

    logger.info(f"DEBUG: All applications before filtering: {len(applications)}")

    # Filter out applications that only have unknown statuses (no valid statuses)
    valid_applications = {}
    for app_id, app_data in applications.items():
        if app_data["statuses"]:  # Only include applications that have at least one valid status
            valid_applications[app_id] = app_data

    # Calculate response rate
    total_applications = len(valid_applications)
    if total_applications == 0:
        return {"value": 0.0}

    # Count applications that received a response (not just application confirmation or rejection)
    responses_received = 0
    
    for app_id, app_data in valid_applications.items():
        statuses = app_data["statuses"]
        
        # Check if this application received any response beyond initial confirmation/rejection
        has_response = any(status not in ["application confirmation", "rejection"] for status in statuses)
        
        if has_response:
            responses_received += 1

    response_rate_percent = (responses_received / total_applications) * 100
    return {"value": round(response_rate_percent, 1)}
    
