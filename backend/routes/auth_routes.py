import logging
from fastapi import APIRouter, Depends, HTTPException, Request, BackgroundTasks
from fastapi.responses import RedirectResponse
from google_auth_oauthlib.flow import Flow

from db.utils.user_utils import user_exists
from utils.auth_utils import AuthenticatedUser, get_google_authorization_url, get_refresh_token_status, get_creds, get_latest_refresh_token
from session.session_layer import create_random_session_string, validate_session, get_token_expiry, clear_session
from utils.config_utils import get_settings
from utils.cookie_utils import set_conditional_cookie
from utils.redirect_utils import Redirects
from routes.email_routes import fetch_emails_to_db
import database
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

# Logger setup
logger = logging.getLogger(__name__)

# Get settings
settings = get_settings()

# FastAPI router for Google login
router = APIRouter()

APP_URL = settings.APP_URL


@router.get("/auth/google")
@limiter.limit("10/minute")
async def login(
    request: Request, background_tasks: BackgroundTasks, db_session: database.DBSession
):
    """Handles Google OAuth2 login and authorization code exchange."""
    code = request.query_params.get("code")

    flow = Flow.from_client_config(
        settings.google_oauth2_config,
        settings.GOOGLE_SCOPES,
        redirect_uri=settings.REDIRECT_URI,
    )
    try:
        if not code:
            # Check if we have a refresh token in session
            has_refresh_token = get_refresh_token_status(request.session.get("creds"))
            authorization_url, state = get_google_authorization_url(
                flow, has_refresh_token
            )
            request.session["oauth_state"] = state
            return RedirectResponse(url=authorization_url)
        
        # OAuth callback - verify state
        saved_state = request.session.pop("oauth_state", None)
        query_params_state = request.query_params.get("state")

        if not saved_state or saved_state != query_params_state:
            logger.error("CSRF attack detected: session state mismatch or missing.")
            # 1. Build the error response
            response = Redirects.to_error("session_mismatch")
            # 2. Clear server-side session
            clear_session(request, response)
            # 3. Explicitly delete cookies on THIS response
            # Ensure domain matches your production settings if applicable
            response.delete_cookie(key="__Secure-Authorization", domain=settings.ORIGIN)
            response.delete_cookie(key="Authorization")

            return response

        creds = get_creds(request=request, code=code, flow=flow, state=query_params_state)
        if isinstance(creds, RedirectResponse):
            return creds
        user = AuthenticatedUser(creds)
        # Preserve existing session_id or create new one if none exists
        session_id = request.session.get("session_id") or create_random_session_string()
        request.session["session_id"] = session_id

        # Set session details
        request.session["token_expiry"] = get_token_expiry(creds)
        request.session["user_id"] = user.user_id
        request.session["access_token"] = creds.token
        request.session["creds"] = get_latest_refresh_token(old_creds=request.session.get("creds"), new_creds=creds)

        existing_user, last_fetched_date = user_exists(user, db_session)
        if existing_user and existing_user.is_active:
            response = Redirects.to_processing()
            background_tasks.add_task(
                fetch_emails_to_db,
                user,
                request,
                last_fetched_date,
                user_id=user.user_id,
                db_session=db_session,
            )
            logger.info("fetch_emails_to_db task started for user_id: %s fetching as of %s", user.user_id, last_fetched_date)
        else:
            logger.warning("user_id: %s is not active. Redirecting to inactive account page.", user.user_id)
            return Redirects.to_error("account_inactive")

        response = set_conditional_cookie(
            key="Authorization", value=session_id, response=response
        )
        return response
    except Exception as e:
        logger.error("Catchall login error: %s", e)
        return Redirects.to_error("oops")

@router.get("/logout")
async def logout(request: Request, response: RedirectResponse):
    logger.info("Logging out")
    request.session.clear()
    response.delete_cookie(key="__Secure-Authorization")
    response.delete_cookie(key="Authorization")
    return RedirectResponse(f"{APP_URL}", status_code=303)


@router.get("/me")
async def getUser(request: Request, user_id: str = Depends(validate_session)):
    if not user_id:
        raise HTTPException(status_code=401, detail="No user id found in session")
    return {"user_id": user_id}
