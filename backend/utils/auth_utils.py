import json
import logging


from fastapi.responses import RedirectResponse

from utils.file_utils import get_user_filepath

from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google.oauth2 import id_token
from googleapiclient.discovery import build
from utils.config_utils import get_settings

logger = logging.getLogger(__name__)

settings = get_settings()

class AuthenticatedUser:
    """
    The AuthenticatedUser class is used to
    store information about the user. This
    class is instantiated after the user has
    successfully authenticated with Google.
    """

    def __init__(
        self,
        creds: Credentials,
        start_date=None,
        _user_id=None,
        _user_email=None,
        _service=None,
    ):
        self.creds = creds
        self.auth_time = None
        self.user_id, self.user_email = (
            (_user_id, _user_email)
            if _user_id and _user_email
            else self.get_user_id_and_email()
        )
        self.filepath = get_user_filepath(self.user_id)
        self.start_date = start_date
        self.service = _service if _service else build("gmail", "v1", credentials=creds)

    def get_user_id_and_email(self) -> tuple:
        """
        Retrieves the user ID, email from Google OAuth2 credentials.

        Parameters:

        Returns:
        - user_id: The unique user ID.
        - email: The user's email address.
        """
        try:
            logger.info("Verifying ID token...")

            # Ensure we have an ID token
            if not self.creds.id_token:
                logger.warning("ID token is missing, trying to refresh credentials...")
                self.creds.refresh(Request())  # Refresh credentials

            # If still missing, raise an error
            if not self.creds.id_token:
                raise ValueError("No ID token available after refresh.")
    
            decoded_token = id_token.verify_oauth2_token(
                self.creds.id_token, Request(), audience=self.creds.client_id
            )
            user_id = decoded_token["sub"]  # 'sub' is the unique user ID
            user_email = decoded_token.get("email")  # 'email' is the user's email address
            return user_id, user_email
        
        except (KeyError, TypeError):
            self.creds = self.creds.refresh(Request())
            if not hasattr(self, "_retry"):
                self._retry = True
                return self.get_user_id_and_email()
            else:
                logger.error("Error verifying ID token with _retry")
                raise ValueError("Authentication token is invalid or expired")
        except Exception as e:
            logger.error("Error verifying ID token: %s", e)
            raise ValueError("Authentication token is invalid or expired")


def get_google_authorization_url(flow, has_valid_creds: bool, step_up: bool = False) -> tuple[str, str]:
    """
    Helper function to generate the Google OAuth2 authorization URL with appropriate prompt.
    Use 'select_account' for returning users (with valid refresh tokens), or 'consent' for new/expired users.
    
    Args:
        flow: Google OAuth2 flow object
        has_valid_creds (bool): Whether the user has valid credentials (refresh token)
        
    Returns:
        tuple[str, str]: (authorization_url, state) from the OAuth flow
    """
    if step_up:
        # Force account selection and re-authentication for sensitive actions
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            prompt='select_account',
            max_age=0  # Enforces a fresh login session
        )
        logger.info("Using select_account with max_age=0 for step-up authentication")
    elif has_valid_creds:
        # Returning user - use select_account (no consent screen)
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            prompt='select_account'
        )
        logger.info("Using select_account for returning user (skip consent)")
    else:
        # New user or user without refresh token - use consent
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            prompt='consent'
        )
        logger.info("Using consent for new user or user without refresh token")
    
    return authorization_url, state


def get_refresh_token_status(
    db_session=None,
    user_id: str = None,
    credential_type: str = None,
) -> bool:
    """Check if user has a valid refresh token.

    Args:
        db_session: Database session for DB credential lookup
        user_id: User ID for DB credential lookup
        credential_type: email_sync or primary string

    Returns:
        True if refresh token exists (in DB), False otherwise
    """
    if not db_session or not user_id:
        return False
    
    from utils.credential_service import load_credentials

    # If a specific type is requested, only check that type
    types_to_check = [credential_type] if credential_type else ["email_sync", "primary"]

    for cred_type in types_to_check:
        creds = load_credentials(
            db_session, user_id, cred_type, auto_refresh=False
        )
        if creds and creds.refresh_token:
            logger.info(
                "Found valid refresh token in DB (%s) for user %s",
                cred_type,
                user_id,
            )
            return True

    return False


def get_creds(request, code, flow: Flow):
    """
    Get credentials from token authentication. Handles redirects as needed to get user permission.
    This will be simplified when we start storing the refresh tokens in persistent storage.
    """
    logger.info("Authorization code received, exchanging for token...")
    # fetch token
    try:
        flow.fetch_token(code=code)
    except Exception as e:
        logger.error("Failed to fetch token: %s", e)
        return RedirectResponse(
            url=f"{settings.APP_URL}/errors?message=permissions_error",
            status_code=303,
        )
    # fetch creds, check if valid, else, refresh creds
    try:
        creds = flow.credentials
        logger.info(
            "Credentials received - returning creds, has_refresh_token: %s",
            bool(creds.refresh_token),
        )
        if not creds.valid:
            logger.info("Invalid credentials")
            try:
                creds.refresh(Request())
            except Exception as e:
                logger.info("Trouble refreshing creds: %s", e)
                return RedirectResponse("/auth/google", status_code=303)
        return creds
    except Exception as e:
        logger.error("Failed to fetch credentials: %s", e)
        return RedirectResponse(
            url=f"{settings.APP_URL}/errors?message=credentials_error",
            status_code=303,
        )


def get_latest_refresh_token(old_creds, new_creds: Credentials) -> Credentials:
    """Preserves the refresh token from old credentials if the new ones don't have it."""
    if not new_creds.refresh_token and old_creds:
        old_refresh_token = None
        
        # Check if old_creds is a Credentials object (from DB load)
        if hasattr(old_creds, 'refresh_token') and old_creds.refresh_token:
            old_refresh_token = old_creds.refresh_token
        # Check if old_creds is a JSON string (legacy session fallback)
        elif isinstance(old_creds, str):
            try:
                old_dict = json.loads(old_creds)
                if old_dict.get("refresh_token"):
                    old_refresh_token = old_dict["refresh_token"]
            except Exception as e:
                logger.warning("Failed to preserve refresh token from old credentials: %s", str(e))
        
        if old_refresh_token:
            # Re-instantiate the Credentials object to bypass the read-only property restriction
            new_creds = Credentials(
                token=new_creds.token,
                refresh_token=old_refresh_token,
                id_token=new_creds.id_token,
                token_uri=new_creds.token_uri,
                client_id=new_creds.client_id,
                client_secret=new_creds.client_secret,
                scopes=new_creds.scopes,
                expiry=new_creds.expiry
            )
                
    return new_creds