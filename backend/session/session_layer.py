# app/session/session_layer.py
import logging
import secrets
from datetime import datetime, timezone, timedelta
from fastapi import Request, Response
from utils.config_utils import get_settings
import database
from db.users import Users
from sqlmodel import select

logger = logging.getLogger(__name__)

settings = get_settings()


def create_random_session_string() -> str:
    return secrets.token_urlsafe(32)  # Generates a random URL-safe string


def clear_session(request: Request, response: Response) -> None:
    # 1. Clear the Starlette/FastAPI session storage
    request.session.clear() 

    # 2. Delete the primary auth cookies
    # We delete both the prefixed and non-prefixed versions to be safe 
    # across dev/prod environments
    response.delete_cookie(key="Authorization")
    response.delete_cookie(key="__Secure-Authorization", domain=settings.ORIGIN)
    response.delete_cookie(key="__Host-Authorization")
    
    # 3. Also clear the SessionMiddleware cookie itself
    response.delete_cookie(key="session", domain=settings.ORIGIN)

    logger.warning("Session and cookies cleared for security.")

def validate_session(request: Request, db_session: database.DBSession) -> str:
    """Retrieves Authorization, session_id, access_token and token_expiry
    from request cookies and validates them.
    Session ID should match the stored session.
    Access token should not be expired.
    """
    if settings.is_publicly_deployed:
        session_authorization = request.cookies.get("__Secure-Authorization")
    else:
        session_authorization = request.cookies.get("Authorization")

    session_id = request.session.get("session_id")
    session_access_token = request.session.get("access_token")
    token_exp = request.session.get("token_expiry")
    user_id = request.session.get("user_id")

    if not session_authorization and not session_access_token:
        logger.info(
            "No Authorization and access_token in session, redirecting to login"
        )
        return ""

    if session_authorization != session_id:
        logger.info("Authorization does not match Session Id, redirecting to login")
        return ""

    if is_token_expired(token_exp):
        logger.info("Access_token is expired, redirecting to login")
        return ""

    if user_id:
        # check that user actually exists in database first
        logger.info("validate_session found user_id: %s", user_id)
        db_session.expire_all()  # Clear any cached data
        db_session.commit()  # Commit pending changes to ensure the database is in latest state
        user = db_session.exec(select(Users).where(Users.user_id == user_id)).first()
        if not user or not user.is_active:
            clear_session(request, user_id)
            logger.info("validate_session deleting user_id: %s", user_id)
            return ""

    logger.info("Valid Session, Access granted.")
    return user_id


def get_token_expiry(creds) -> str:
    try:
        token_expiry = creds.expiry.isoformat()
    except Exception as e:
        logger.error("Failed to parse token expiry: %s", e)
        token_expiry = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    return token_expiry


def is_token_expired(iso_expiry: str) -> bool:
    """
    Converts ISO format timestamp (which serves as the expiry time of the token) to datetime.
    If the current time is greater than the expiry time,
    the token is expired.
    """
    if iso_expiry:
        datetime_expiry = datetime.fromisoformat(iso_expiry)  # UTC time
        if datetime_expiry.tzinfo is None:
            datetime_expiry = datetime_expiry.replace(tzinfo=timezone.utc)
        difference_in_minutes = (
            datetime_expiry - datetime.now(timezone.utc)
        ).total_seconds() / 60
        return difference_in_minutes <= 0

    return True
