import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, BackgroundTasks
from fastapi.responses import RedirectResponse
from sqlmodel import select
from google_auth_oauthlib.flow import Flow
import secrets
import time

from db.utils.user_utils import user_exists
from utils.auth_utils import AuthenticatedUser, get_google_authorization_url, get_refresh_token_status, get_creds, get_latest_refresh_token
from session.session_layer import clear_session, create_random_session_string, get_token_expiry, validate_session
from utils.billing_utils import is_premium_eligible
from utils.config_utils import get_settings
from utils.cookie_utils import set_conditional_cookie
from utils.credential_service import load_credentials, save_credentials
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


ALLOWED_STEP_UP_PATHS = {
    "/settings",
    "/settings/billing",
    "/dashboard"
}

def get_safe_redirect_url(request: Request, return_to: str, default_url: str) -> str:
    """
    Prevents Open Redirect vulnerabilities by ensuring the return_to path
    is explicitly allowed or strictly a relative path.
    """
    default_url = f"{settings.APP_URL}/dashboard"
    if not return_to or return_to not in ALLOWED_STEP_UP_PATHS:
        request.session["return_to"] = default_url # Store a safe default if not provided
    # 1. Check against a strict allowlist (Safest approach)
    if return_to in ALLOWED_STEP_UP_PATHS:
        request.session["return_to"] = f"{settings.APP_URL}{return_to}"
        return f"{settings.APP_URL}{return_to}"
    # If it fails validation, default to a safe known path
    logger.warning(f"Blocked potential open redirect attempt to: {return_to}")
    return default_url


@router.get("/auth/google")
@limiter.limit("10/minute")
async def login(
    request: Request, background_tasks: BackgroundTasks, db_session: database.DBSession,
    step_up: bool = False,
    return_to: str = None
):
    """Handles Google OAuth2 login and authorization code exchange."""
    code = request.query_params.get("code")

    flow = Flow.from_client_config(
        settings.google_oauth2_config,
        settings.GOOGLE_SCOPES,
        redirect_uri=settings.GOOGLE_CLIENT_REDIRECT_URI,
    )
    try:
        if not code:
            if step_up:
                request.session["is_step_up"] = True
            if return_to:
                # Store the raw return_to, we will validate it upon return
                request.session["return_to"] = return_to
            # Check if we have a refresh token (DB first, then session fallback)
            session_user_id = request.session.get("user_id")
            has_refresh_token = get_refresh_token_status(
                db_session=db_session,
                user_id=session_user_id,
            )
            authorization_url, state = get_google_authorization_url(
                flow, has_refresh_token
            )
            request.session["oauth_state"] = state
            request.session["oauth_start_time"] = time.time()
            return RedirectResponse(url=authorization_url)
        
        # ensure the login link (the "out of band verifier") expires in 10 minutes
        start_time = request.session.pop("oauth_start_time", 0)
        if time.time() - start_time > 600: # 600 seconds = 10 minutes
            logger.error("OAuth flow timed out (exceeded 10 minutes)")
            return Redirects.to_error("timeout")
        
        # OAuth callback - verify state
        saved_state = request.session.pop("oauth_state", None)
        query_params_state = request.query_params.get("state")

        if not saved_state or not secrets.compare_digest(saved_state, query_params_state):
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

        creds = get_creds(request=request, code=code, flow=flow)
        if isinstance(creds, RedirectResponse):
            return creds
        user = AuthenticatedUser(creds)
        # Preserve existing session_id or create new one if none exists
        session_id = request.session.get("session_id") or create_random_session_string()
        request.session["session_id"] = session_id
        request.session["last_login_time"] = datetime.now(timezone.utc).timestamp()
        # Set session details
        request.session["token_expiry"] = get_token_expiry(creds)
        request.session["user_id"] = user.user_id
        
        if user.user_email:
            request.session["user_email"] = user.user_email
        
        is_step_up = request.session.pop("is_step_up", False)
        raw_return_to = request.session.pop("return_to", None)

        existing_user, last_fetched_date = user_exists(user, db_session)

        # Only persist credentials to DB for premium users (data minimization)
        if existing_user:
            old_creds = load_credentials(db_session, user.user_id, credential_type="primary", auto_refresh=False)
            creds = get_latest_refresh_token(old_creds=old_creds, new_creds=creds)
            save_credentials(db_session, user.user_id, creds, credential_type="primary")
            logger.info("Saved/updated credentials for user %s", user.user_id)

        # Default to False for existing users, will be overwritten if needed
        request.session["is_new_user"] = False 

        response = None # Initialize response with a default value
        if existing_user and existing_user.is_active:
            if is_step_up:
                safe_url = get_safe_redirect_url(request=request, return_to=raw_return_to, default_url=f"{APP_URL}/settings")
                response = RedirectResponse(url=safe_url, status_code=303)

            from db.user_emails import UserEmails
            from sqlmodel import func

            # Auto-set start_date from earliest email if not set
            if existing_user.start_date is None:
                earliest_email = db_session.exec(
                    select(func.min(UserEmails.received_at))
                    .where(UserEmails.user_id == user.user_id)
                ).first()
                if earliest_email:
                    existing_user.start_date = earliest_email
                    db_session.add(existing_user)
                    db_session.commit()
                    logger.info("Auto-set start_date for user_id: %s to %s", user.user_id, earliest_email)
                else:
                    request.session["is_new_user"] = True

            # Now set the start_date in session if it exists in the user record
            if existing_user.start_date is not None:
                request.session["start_date"] = existing_user.start_date.strftime("%Y/%m/%d")

            # Redirect based on user status
            if existing_user.role == "coach":
                # Coaches go directly to dashboard
                response = Redirects.to_dashboard()
            elif existing_user.onboarding_completed_at is None:
                # Check if user has any emails in user_emails table
                earliest_email = db_session.exec(
                    select(func.min(UserEmails.received_at))
                    .where(UserEmails.user_id == user.user_id)
                ).first()

                if earliest_email:
                    # User has emails - auto-complete onboarding using earliest email date as start_date
                    existing_user.onboarding_completed_at = datetime.now(timezone.utc)
                    existing_user.start_date = earliest_email
                    db_session.add(existing_user)
                    db_session.commit()
                    logger.info("Auto-completed onboarding for beta user_id: %s with start_date: %s", user.user_id, earliest_email)

                    if not existing_user.has_email_sync_configured:
                        response = Redirects.to_email_sync_setup()
                    else:
                        response = Redirects.to_dashboard()
                else:
                    # No emails - send user through onboarding flow
                    response = Redirects.to_onboarding()
            elif not existing_user.has_email_sync_configured:
                # User completed onboarding but hasn't set up email sync
                response = Redirects.to_email_sync_setup()
            elif existing_user.start_date is None:
                # User needs to pick start date
                response = Redirects.to_dashboard()
            else:
                if not is_step_up:
                    response = Redirects.to_dashboard()
                    background_tasks.add_task(
                        fetch_emails_to_db,
                        user,
                        request,
                        last_fetched_date,
                        user_id=user.user_id,
                    )
                    logger.info("fetch_emails_to_db task started for user_id: %s fetching as of %s", user.user_id, last_fetched_date)
        elif existing_user and not existing_user.is_active:
            # Existing but inactive user - redirect to signup to reactivate
            logger.info("user_id: %s is inactive. Redirecting to signup flow.", user.user_id)
            return Redirects.to_signup()
        else:
            # New user trying to login - redirect to signup flow
            logger.info("user_id: %s does not exist. Redirecting to signup flow.", user.user_id)
            return Redirects.to_signup()

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
    clear_session(request, response)
    return RedirectResponse(f"{APP_URL}", status_code=303)


@router.get("/me")
async def getUser(request: Request, db_session: database.DBSession, user_id: str = Depends(validate_session)):
    if not user_id:
        raise HTTPException(status_code=401, detail="No user id found in session")
    # Fetch user data
    from db.users import Users, CoachClientLink
    user = db_session.exec(select(Users).where(Users.user_id == user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Check if user has an active coach
    active_coach_link = db_session.exec(
        select(CoachClientLink)
        .where(CoachClientLink.client_id == user_id)
        .where(CoachClientLink.end_date.is_(None))
    ).first()

    return {
        "user_id": user_id,
        "role": user.role,
        "has_completed_onboarding": user.onboarding_completed_at is not None,
        "has_email_sync_configured": user.has_email_sync_configured,
        "sync_email_address": user.sync_email_address,
        "is_supporter": (user.monthly_contribution_cents or 0) > 0,
        "supporter_since": user.contribution_started_at.isoformat() if user.contribution_started_at else None,
        "has_active_coach": active_coach_link is not None
    }


@router.get("/auth/google/signup")
@limiter.limit("10/minute")
async def signup(request: Request, db_session: database.DBSession):
    """
    Google OAuth2 signup flow with BASIC scopes only (no email read access).
    Used for new users coming from the pricing page.
    After successful auth, redirects to /onboarding.
    """
    code = request.query_params.get("code")

    # Use basic scopes (openid + email only, no gmail.readonly)
    flow = Flow.from_client_config(
        settings.google_oauth2_config,
        settings.GOOGLE_SCOPES_BASIC,
        redirect_uri=f"{settings.API_URL}/auth/google/signup",
    )
    try:
        if not code:
            # Check if we have a refresh token (DB first, then session fallback)
            session_user_id = request.session.get("user_id")
            has_refresh_token = get_refresh_token_status(
                db_session=db_session,
                user_id=session_user_id,
            )
            authorization_url, state = get_google_authorization_url(
                flow, has_refresh_token
            )
            request.session["oauth_state"] = state
            return RedirectResponse(url=authorization_url)

        # OAuth callback - verify state
        saved_state = request.session.pop("oauth_state", None)
        query_params_state = request.query_params.get("state")

        if not saved_state or not secrets.compare_digest(saved_state, query_params_state):
            logger.error("CSRF attack detected: session state mismatch or missing.")
            response = Redirects.to_error("session_mismatch")
            clear_session(request, response)
            response.delete_cookie(key="__Secure-Authorization", domain=settings.ORIGIN)
            response.delete_cookie(key="Authorization")
            return response

        creds = get_creds(request=request, code=code, flow=flow)
        if isinstance(creds, RedirectResponse):
            return creds
        user = AuthenticatedUser(creds)

        session_id = request.session.get("session_id") or create_random_session_string()
        request.session["session_id"] = session_id
        request.session["token_expiry"] = get_token_expiry(creds)
        request.session["user_id"] = user.user_id
        request.session["last_login_time"] = datetime.now(timezone.utc).timestamp()
        if user.user_email:
            request.session["user_email"] = user.user_email
        
        existing_user, _ = user_exists(user, db_session)

        if existing_user and existing_user.is_active:
            # Existing active user - redirect based on their status
            if existing_user.onboarding_completed_at is not None:
                if existing_user.has_email_sync_configured:
                    response = Redirects.to_dashboard()
                else:
                    response = Redirects.to_email_sync_setup()
            else:
                # Not onboarded yet - go to onboarding
                response = Redirects.to_onboarding()
        elif existing_user and not existing_user.is_active:
            # Existing but inactive user - activate them and send to onboarding
            existing_user.is_active = True
            db_session.add(existing_user)
            db_session.commit()
            logger.info("Activated existing user_id: %s through signup flow", user.user_id)
            response = Redirects.to_onboarding()
        else:
            # New user - create account and redirect to onboarding
            from db.users import Users
            new_user = Users(
                user_id=user.user_id,
                user_email=user.user_email,
                is_active=True,
                start_date=None  # Will be set later
            )
            db_session.add(new_user)
            db_session.commit()
            logger.info("Created new user_id: %s through signup flow", user.user_id)
            request.session["is_new_user"] = True
            response = Redirects.to_onboarding()
        
        old_creds = load_credentials(db_session, user.user_id, credential_type="primary", auto_refresh=False)
        latest_creds = get_latest_refresh_token(old_creds=old_creds, new_creds=creds)
        save_credentials(db_session, user.user_id, latest_creds, credential_type="primary")

        response = set_conditional_cookie(
            key="Authorization", value=session_id, response=response
        )
        return response
    except Exception as e:
        logger.error("Catchall signup error: %s", e)
        return Redirects.to_error("oops")


@router.get("/auth/google/email-sync")
@limiter.limit("10/minute")
async def email_sync_auth(
    request: Request, background_tasks: BackgroundTasks, db_session: database.DBSession
):
    """
    Google OAuth2 for email sync with FULL scopes (gmail.readonly).
    Used after payment to connect a Gmail account for email syncing.
    Can be a different Google account than the signup account.
    Requires user to be authenticated already.
    """
    from db.users import Users

    code = request.query_params.get("code")

    # Use full scopes including gmail.readonly
    flow = Flow.from_client_config(
        settings.google_oauth2_config,
        settings.GOOGLE_SCOPES,
        redirect_uri=f"{settings.API_URL}/auth/google/email-sync",
    )

    try:
        if not code:
            # Check if user is authenticated
            user_id = request.session.get("user_id")
            if not user_id:
                logger.warning("Email sync auth attempted without session. Redirecting to login.")
                return Redirects.to_error("auth_required")

            # Check for email_sync credentials (DB first, then session fallback)
            has_refresh_token = get_refresh_token_status(
                db_session=db_session,
                user_id=user_id,
                credential_type="email_sync"
            )
            authorization_url, state = get_google_authorization_url(
                flow, has_refresh_token
            )
            request.session["email_sync_oauth_state"] = state
            return RedirectResponse(url=authorization_url)

        # OAuth callback - verify state
        saved_state = request.session.pop("email_sync_oauth_state", None)
        query_params_state = request.query_params.get("state")

        if not saved_state or not secrets.compare_digest(saved_state, query_params_state):
            logger.error("CSRF attack detected in email sync: session state mismatch or missing.")
            return Redirects.to_error("session_mismatch")

        # Get authenticated user
        user_id = request.session.get("user_id")
        if not user_id:
            logger.warning("Email sync callback without user_id in session.")
            return Redirects.to_error("auth_required")

        creds = get_creds(request=request, code=code, flow=flow)
        if isinstance(creds, RedirectResponse):
            return creds

        # Create AuthenticatedUser for the email sync account (may be different from signup account)
        initial_sync_user = AuthenticatedUser(creds)

        user = db_session.exec(select(Users).where(Users.user_id == user_id)).first()
        if not user:
            return Redirects.to_error("auth_required")

        old_creds_from_db = load_credentials(db_session, user_id, credential_type="email_sync", auto_refresh=False)
        creds_to_save = get_latest_refresh_token(old_creds=old_creds_from_db, new_creds=creds)
        save_credentials(db_session, user_id, creds_to_save, credential_type="email_sync")
        # Update user record with email sync info
        logger.info("Saved email_sync credentials for premium user %s", user_id)

        # Load final credentials for the background task, refreshing if needed
        should_auto_refresh = is_premium_eligible(db_session, user) if user else False
        final_creds_for_task = load_credentials(db_session, user_id, credential_type="email_sync", auto_refresh=should_auto_refresh)
        
        if not final_creds_for_task:
             logger.error("Could not load final credentials for background task for user %s", user_id)
             return Redirects.to_error("token_error")

        # Create AuthenticatedUser for the task with final creds, reusing user info
        sync_user_for_task = AuthenticatedUser(
            final_creds_for_task,
            _user_id=initial_sync_user.user_id,
            _user_email=initial_sync_user.user_email
        )

        # Update user record with email sync info
        user.has_email_sync_configured = True
        user.sync_email_address = initial_sync_user.user_email
        db_session.add(user)
        db_session.commit()
        logger.info("Email sync configured for user_id: %s", user_id)

        # Get last fetched date for incremental sync
        from db.utils.user_utils import get_last_email_date
        last_fetched_date = get_last_email_date(user_id, db_session)

        # Trigger email fetch in background
        background_tasks.add_task(
            fetch_emails_to_db,
            sync_user_for_task,
            request,
            last_fetched_date,
            user_id=user_id,
        )
        logger.info("fetch_emails_to_db task started for user_id: %s", user_id)

        response = Redirects.to_dashboard()
        return response

    except Exception as e:
        logger.error("Catchall email sync auth error: %s", e)
        return Redirects.to_error("oops")
