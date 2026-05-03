import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from email_validator import validate_email, EmailNotValidError
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlmodel import select

import database
from db.users import Users
from session.session_layer import validate_session

limiter = Limiter(key_func=get_remote_address)
logger = logging.getLogger(__name__)
router = APIRouter()


class EmailSignupRequest(BaseModel):
    email: str


class ConsentUpdateRequest(BaseModel):
    consent: bool


@router.post("/api/email-signup")
@limiter.limit("5/minute")
async def email_signup(
    request: Request,
    body: EmailSignupRequest,
    db_session: database.DBSession,
):
    """Public landing-page email signup that captures founder-updates consent.

    Creates a lightweight Users row if no user exists with this email; otherwise
    flips the consent flag to True (preserving existing consent timestamp).

    Always returns 200 to avoid email enumeration. Reconciles automatically with
    a future Google OAuth login via the existing user_exists() helper.
    """
    try:
        validated = validate_email(body.email, check_deliverability=False)
        email_normalized = validated.normalized
    except EmailNotValidError:
        raise HTTPException(status_code=400, detail="Invalid email address")

    existing = db_session.exec(
        select(Users).where(Users.user_email == email_normalized)
    ).first()

    now = datetime.now(timezone.utc)

    if existing:
        if not existing.email_marketing_consent:
            existing.email_marketing_consent = True
            existing.email_marketing_consent_at = now
            db_session.add(existing)
            db_session.commit()
            logger.info("email_signup: re-opted in existing user_email")
    else:
        new_user = Users(
            user_id=str(uuid.uuid4()),
            user_email=email_normalized,
            start_date=None,
            email_marketing_consent=True,
            email_marketing_consent_at=now,
        )
        db_session.add(new_user)
        db_session.commit()
        logger.info("email_signup: created lite user record")

    return {"ok": True}


@router.put("/settings/email-marketing-consent")
@limiter.limit("10/minute")
async def update_email_marketing_consent(
    request: Request,
    body: ConsentUpdateRequest,
    db_session: database.DBSession,
    user_id: str = Depends(validate_session),
):
    """Set the authenticated user's founder-updates consent.

    Timestamp tracks the CURRENT opted-in state, not historical consent:
      - true,  was false -> flag=true,  timestamp=now()
      - true,  was true  -> no-op
      - false, was true  -> flag=false, timestamp=null
      - false, was false -> no-op
    """
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = db_session.get(Users, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if body.consent and not user.email_marketing_consent:
        user.email_marketing_consent = True
        user.email_marketing_consent_at = datetime.now(timezone.utc)
        db_session.add(user)
        db_session.commit()
    elif not body.consent and user.email_marketing_consent:
        user.email_marketing_consent = False
        user.email_marketing_consent_at = None
        db_session.add(user)
        db_session.commit()

    return {
        "email_marketing_consent": user.email_marketing_consent,
        "email_marketing_consent_at": (
            user.email_marketing_consent_at.isoformat()
            if user.email_marketing_consent_at
            else None
        ),
    }
