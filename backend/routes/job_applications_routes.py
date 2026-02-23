from datetime import datetime
import email.utils
from fastapi import APIRouter, Depends, Request, HTTPException
import logging
from pydantic import BaseModel, Field, field_validator
from sqlmodel import select, and_
from typing import Optional
import uuid

from db.user_emails import UserEmails
from session.session_layer import validate_session
import database
from slowapi import Limiter
from slowapi.util import get_remote_address
from utils.validator_utils import reject_html_svg

limiter = Limiter(key_func=get_remote_address)
logger = logging.getLogger(__name__)

router = APIRouter()


# Request/Response models
class JobApplicationCreate(BaseModel):
    company_name: str = Field(..., max_length=255)
    application_status: str = Field(..., max_length=50)
    received_at: datetime
    subject: str = Field(..., max_length=1000)
    job_title: str = Field(..., max_length=255)
    email_from: str = Field(default="", max_length=255)

    @field_validator('company_name', 'application_status', 'subject', 'job_title')
    @classmethod
    def validate_no_markup(cls, v):
        return reject_html_svg(v)
    
    @field_validator('email_from')
    @classmethod
    def parse_and_validate_email_from(cls, v: str) -> str:
        # Parse out the angle brackets before your global XSS validator trips
        _, parsed_email = email.utils.parseaddr(v)
        
        # If it parsed successfully, you can store just the email, 
        # or format it safely without the brackets if your system demands it.
        if parsed_email:
            return parsed_email
        return reject_html_svg(v)

class JobApplicationUpdate(BaseModel):
    company_name: Optional[str] = Field(default=None, max_length=255)
    application_status: Optional[str] = Field(default=None, max_length=50)
    received_at: Optional[datetime] = Field(default=None)
    subject: Optional[str] = Field(default=None, max_length=1000)
    job_title: Optional[str] = Field(default=None, max_length=255)
    email_from: Optional[str] = Field(default=None, max_length=255)

    @field_validator('company_name', 'application_status', 'subject', 'job_title')
    @classmethod
    def validate_no_markup(cls, v):
        return reject_html_svg(v)

    @field_validator('email_from')
    @classmethod
    def parse_and_validate_email_from(cls, v: str) -> str:
        # Parse out the angle brackets before your global XSS validator trips
        _, parsed_email = email.utils.parseaddr(v)
        
        # If it parsed successfully, you can store just the email, 
        # or format it safely without the brackets if your system demands it.
        if parsed_email:
            return parsed_email
        return reject_html_svg(v)

class JobApplicationResponse(BaseModel):
    id: str
    company_name: str
    application_status: str
    received_at: datetime
    subject: str
    job_title: str
    email_from: str

@router.post("/job-applications", response_model=JobApplicationResponse)
@limiter.limit("10/minute")
async def create_job_application(
    request: Request,
    application: JobApplicationCreate,
    db_session: database.DBSession,
    user_id: str = Depends(validate_session)
):
    """
    Create a new job application manually.
    """
    try:
        logger.info(f"Creating job application for user_id: {user_id}")
        
        # Generate a unique ID for the manual application
        manual_app_id = f"manual_{uuid.uuid4().hex[:8]}_{int(datetime.now().timestamp())}"
        
        # Create new UserEmails record (which serves as job application record)
        new_application = UserEmails(
            id=manual_app_id,
            user_id=user_id,
            company_name=application.company_name,
            application_status=application.application_status,
            received_at=application.received_at,
            subject=application.subject,
            job_title=application.job_title,
            email_from=application.email_from or "Manually Added"
        )
        
        db_session.add(new_application)
        db_session.commit()
        db_session.refresh(new_application)
        
        logger.info(f"Successfully created job application with id: {manual_app_id}")
        
        return JobApplicationResponse(
            id=new_application.id,
            company_name=new_application.company_name,
            application_status=new_application.application_status,
            received_at=new_application.received_at,
            subject=new_application.subject,
            job_title=new_application.job_title,
            email_from=new_application.email_from
        )
        
    except Exception as e:
        error_id = uuid.uuid4()
        logger.exception(f"Error {error_id} creating job application for user_id {user_id}: {e}")
        db_session.rollback()
        raise HTTPException(status_code=500, detail=f"An internal error occurred. Reference ID: {error_id}")

@router.put("/job-applications/{application_id}", response_model=JobApplicationResponse)
@limiter.limit("10/minute")
async def update_job_application(
    request: Request,
    application_id: str,
    application_update: JobApplicationUpdate,
    db_session: database.DBSession,
    user_id: str = Depends(validate_session)
):
    """
    Update an existing job application.
    """
    try:
        logger.info(f"Updating job application {application_id} for user_id: {user_id}")
        
        # Find the existing application
        statement = select(UserEmails).where(
            and_(UserEmails.id == application_id, UserEmails.user_id == user_id)
        )
        existing_application = db_session.exec(statement).first()
        
        if not existing_application:
            raise HTTPException(
                status_code=404, 
                detail=f"Job application with id {application_id} not found"
            )
        
        # Update only the fields that were provided
        update_data = application_update.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(existing_application, field, value)
        
        db_session.add(existing_application)
        db_session.commit()
        db_session.refresh(existing_application)
        
        logger.info(f"Successfully updated job application with id: {application_id}")
        
        return JobApplicationResponse(
            id=existing_application.id,
            company_name=existing_application.company_name,
            application_status=existing_application.application_status,
            received_at=existing_application.received_at,
            subject=existing_application.subject,
            job_title=existing_application.job_title,
            email_from=existing_application.email_from
        )
        
    except HTTPException:
        raise
    except Exception as e:
        error_id = uuid.uuid4()
        logger.exception(f"Error {error_id} updating job application for user_id {user_id}: {e}")
        db_session.rollback()
        raise HTTPException(status_code=500, detail=f"An internal error occurred. Reference ID: {error_id}")

