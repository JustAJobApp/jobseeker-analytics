# app/session/session_layer.py
from datetime import datetime, timezone
from fastapi import Request, Response
from google.oauth2.credentials import Credentials
import json
import logging
import secrets
from sqlmodel import select

import database
from db.users import Users
from utils.config_utils import get_settings
from utils.credential_service import load_credentials, save_credentials

logger = logging.getLogger(__name__)

settings = get_settings()

# Threshold for proactive token refresh (in minutes)
TOKEN_REFRESH_THRESHOLD_MINUTES = 5


def create_random_session_string() -> str:
    return secrets.token_urlsafe(32)  # Generates a random URL-safe string


def clear_session(request: Request, response: Response) -> None:
    logger.info("clear_session called")
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
    token_exp = request.session.get("token_expiry") # Read from session, NOT db
    user_id = request.session.get("user_id")
    user_email = request.session.get("user_email")

    if not session_authorization or session_authorization != session_id:
        logger.info("Authorization missing or does not match Session Id")
        return ""
    
    if user_id:

        # ==========================================
        # START SILENT MIGRATION FOR EXISTING USERS
        # ==========================================
        
        # 1. Migrate Primary Credentials
        if request.session.get("creds"):
            existing_db_creds = load_credentials(db_session, user_id, "primary", auto_refresh=False)
            if not existing_db_creds:
                try:
                    creds_dict = json.loads(request.session.get("creds"))
                    creds_obj = Credentials.from_authorized_user_info(creds_dict)
                    saved = save_credentials(db_session, user_id, creds_obj, "primary")
                    if saved:
                        logger.info("Migrated primary credentials to database for user %s", user_id)
                    else: 
                        logger.error("Failed to migrate primary credentials for user %s: %s", user_id)
                except Exception as e:
                    logger.error("Failed to migrate primary credentials for user %s: %s", user_id, e)
            
            # ALWAYS clean up the session cookie, even if DB save failed (fail-safe)
            request.session.pop("creds", None)
            request.session.pop("access_token", None)

        # 2. Migrate Email Sync Credentials (if they exist)
        if request.session.get("email_sync_creds"):
            existing_sync_creds = load_credentials(db_session, user_id, "email_sync", auto_refresh=False)
            if not existing_sync_creds:
                try:
                    sync_creds_dict = json.loads(request.session.get("email_sync_creds"))
                    sync_creds_obj = Credentials.from_authorized_user_info(sync_creds_dict)
                    save_credentials(db_session, user_id, sync_creds_obj, "email_sync")
                    logger.info("Migrated email_sync credentials to database for user %s", user_id)
                except Exception as e:
                    logger.error("Failed to migrate email_sync credentials for user %s: %s", user_id, e)
            
            # ALWAYS clean up the session cookie
            request.session.pop("email_sync_creds", None)
            
        # ==========================================
        # END SILENT MIGRATION
        # ==========================================

        # 2. NOW SAFELY FETCH THE USER
        # Load user to check premium status
        db_session.expire_all()
        db_session.commit()
        try:
            user = db_session.exec(select(Users).where(Users.user_email == user_email)).first()
        except Exception:
            logger.info("Unable to load user")
            request.session.clear()
            return ""
            
        if not user or not user.is_active:
            request.session.clear()
            return ""

        if is_token_expired(token_exp) or is_token_near_expiry(token_exp):
            from utils.billing_utils import is_premium_eligible
            if is_premium_eligible(db_session, user):
                logger.info("Premium user token near expiry, attempting refresh")
                if not attempt_token_refresh(request, db_session, user_id):
                    return ""  # refresh failed
                # Continue with validation - token is now valid
            else:
                logger.info("Free user token expired. Forcing re-authentication.")
                request.session.clear()
                return ""

    logger.info("Valid Session, Access granted.")
    return user_id


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


def is_token_near_expiry(iso_expiry: str, threshold_minutes: int = TOKEN_REFRESH_THRESHOLD_MINUTES) -> bool:
    """
    Check if token is expired or will expire within threshold_minutes.
    Used to proactively refresh tokens before they expire.
    """
    if iso_expiry:
        datetime_expiry = datetime.fromisoformat(iso_expiry)
        if datetime_expiry.tzinfo is None:
            datetime_expiry = datetime_expiry.replace(tzinfo=timezone.utc)
        difference_in_minutes = (
            datetime_expiry - datetime.now(timezone.utc)
        ).total_seconds() / 60
        return difference_in_minutes <= threshold_minutes
    return True


def get_token_expiry(creds) -> str:
    try:
        token_expiry = creds.expiry.isoformat()
    except Exception as e:
        logger.error("Failed to parse token expiry: %s", e)
        # Deny access by assuming the token is already expired (Fail-Closed)
        token_expiry = datetime.now(timezone.utc).isoformat()
    return token_expiry


def attempt_token_refresh(
    request: Request,
    db_session: database.DBSession,
    user_id: str,
) -> bool:
    """
    Attempt to refresh expired/near-expiry tokens using stored credentials.

    Returns:
        True if refresh succeeded and session was updated, False otherwise
    """
    from utils.credential_service import load_credentials

    # Try email_sync credentials first, then primary
    for cred_type in ["email_sync", "primary"]:
        creds = load_credentials(
            db_session,
            user_id,
            credential_type=cred_type,
            auto_refresh=True
        )

        if creds and creds.token and creds.expiry:
            # Update session with refreshed tokens
            request.session["token_expiry"] = get_token_expiry(creds)
            return True

    logger.warning("Token refresh failed for user %s - no valid credentials found", user_id)
    return False


def user_has_recent_authentication(request: Request, max_age_minutes: int = 15) -> bool:
    """
    Checks if the user has freshly authenticated recently (Step-Up verification).
    Call this as a dependency or inline check on sensitive routes like subscription changes.
    """
    last_login_str = request.session.get("last_login_time")
    if not last_login_str:
        return False
        
    try:
        last_auth_time = datetime.fromtimestamp(int(last_login_str), tz=timezone.utc)
        if last_auth_time.tzinfo is None:
            last_auth_time = last_auth_time.replace(tzinfo=timezone.utc)
            
        age_in_minutes = int((datetime.now(timezone.utc) - last_auth_time).total_seconds() / 60)
        logger.info("user_id: %s last login at %s or %s minutes ago", request.session["user_id"], last_auth_time, age_in_minutes)
        return age_in_minutes <= max_age_minutes
    except ValueError:
        return False