"""Service for managing encrypted OAuth credentials in the database.

Handles:
- Storing/updating encrypted tokens after OAuth callback
- Loading and decrypting tokens for background tasks
- Proactive token refresh when near expiry
- Graceful fallback to session credentials
"""

import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlmodel import select, Session
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request

from db.oauth_credentials import OAuthCredentials
from utils.encryption_utils import encrypt_token, decrypt_token, EncryptionError
from utils.config_utils import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

# Refresh threshold: refresh if less than 5 minutes remaining
REFRESH_THRESHOLD_MINUTES = 5


def save_credentials(
    db_session: Session,
    user_id: str,
    creds: Credentials,
    credential_type: str = "primary",
) -> bool:
    """Save or update encrypted OAuth credentials.

    Args:
        db_session: Database session
        user_id: User's unique ID
        creds: Google OAuth2 Credentials object
        credential_type: 'primary' for login or 'email_sync' for separate sync account

    Returns:
        True if saved successfully, False otherwise
    """
    try:
        # Validate credential type
        if credential_type not in ("primary", "email_sync"):
            raise ValueError(f"Invalid credential_type: {credential_type}")

        # Encrypt tokens
        encrypted_refresh = encrypt_token(creds.refresh_token) if creds.refresh_token else encrypt_token("")
        encrypted_access = (
            encrypt_token(creds.token) if creds.token else encrypt_token("")
        )

        # Serialize scopes
        scopes_json = json.dumps(list(creds.scopes) if creds.scopes else [])

        # Get token expiry
        token_expiry = creds.expiry
        if token_expiry is None:
            token_expiry = datetime.now(timezone.utc) + timedelta(hours=1)
        elif token_expiry.tzinfo is None:
            token_expiry = token_expiry.replace(tzinfo=timezone.utc)

        # Check for existing credentials
        existing = db_session.exec(
            select(OAuthCredentials)
            .where(OAuthCredentials.user_id == user_id)
            .where(OAuthCredentials.credential_type == credential_type)
        ).first()

        if existing:
            # Update existing record
            existing.encrypted_refresh_token = encrypted_refresh
            existing.encrypted_access_token = encrypted_access
            existing.token_expiry = token_expiry
            existing.scopes = scopes_json
            existing.client_id = creds.client_id or settings.GOOGLE_CLIENT_ID
            db_session.add(existing)
            logger.info("Updated %s credentials for user %s", credential_type, user_id)
        else:
            # Create new record
            new_creds = OAuthCredentials(
                user_id=user_id,
                credential_type=credential_type,
                encrypted_refresh_token=encrypted_refresh,
                encrypted_access_token=encrypted_access,
                token_expiry=token_expiry,
                scopes=scopes_json,
                client_id=creds.client_id or settings.GOOGLE_CLIENT_ID,
            )
            db_session.add(new_creds)
            logger.info("Created %s credentials for user %s", credential_type, user_id)

        db_session.commit()
        return True

    except EncryptionError as e:
        logger.error("Failed to encrypt credentials for user %s: %s", user_id, e)
        return False
    except Exception as e:
        logger.error("Failed to save credentials for user %s: %s", user_id, e)
        db_session.rollback()
        return False


def load_credentials(
    db_session: Session,
    user_id: str,
    credential_type: str = "email_sync",
    auto_refresh: bool = False,
) -> Optional[Credentials]:
    """Load and optionally refresh OAuth credentials from database.

    Args:
        db_session: Database session
        user_id: User's unique ID
        credential_type: 'primary' or 'email_sync'
        auto_refresh: If True, refresh token if near expiry

    Returns:
        Google Credentials object or None if not found/invalid
    """
    try:
        stored = db_session.exec(
            select(OAuthCredentials)
            .where(OAuthCredentials.user_id == user_id)
            .where(OAuthCredentials.credential_type == credential_type)
        ).first()

        if not stored:
            logger.info("No %s credentials found for user %s", credential_type, user_id)
            return None

        # Decrypt tokens
        refresh_token = decrypt_token(stored.encrypted_refresh_token)
        access_token = decrypt_token(stored.encrypted_access_token)

        # Parse scopes
        scopes = json.loads(stored.scopes) if stored.scopes else []

        google_expiry = stored.token_expiry
        if google_expiry and google_expiry.tzinfo is not None:
            # Ensure it is UTC, then strip the timezone info completely
            google_expiry = google_expiry.astimezone(timezone.utc).replace(tzinfo=None)

        # Build credentials object
        creds = Credentials(
            token=access_token if access_token else None,
            refresh_token=refresh_token,
            token_uri=stored.token_uri,
            client_id=stored.client_id,
            client_secret=settings.GOOGLE_CLIENT_SECRET,
            scopes=scopes,
            expiry=google_expiry,
        )

        # Check if refresh needed
        if auto_refresh and _should_refresh(stored.token_expiry):
            logger.info("Token near expiry for user %s, refreshing", user_id)
            creds = _refresh_and_save(db_session, user_id, creds, stored)

        return creds

    except EncryptionError as e:
        logger.error("Failed to decrypt credentials for user %s: %s", user_id, e)
        return None
    except Exception as e:
        logger.error("Failed to load credentials for user %s: %s", user_id, e)
        return None


def _should_refresh(token_expiry: datetime) -> bool:
    """Check if token should be proactively refreshed."""
    if token_expiry is None:
        return True

    # Ensure timezone-aware comparison
    if token_expiry.tzinfo is None:
        token_expiry = token_expiry.replace(tzinfo=timezone.utc)

    time_remaining = token_expiry - datetime.now(timezone.utc)
    return time_remaining.total_seconds() < (REFRESH_THRESHOLD_MINUTES * 60)


def _refresh_and_save(
    db_session: Session,
    user_id: str,
    creds: Credentials,
    stored: OAuthCredentials,
) -> Optional[Credentials]:
    """Refresh token and save updated credentials.

    Returns:
        Refreshed Credentials object or None if refresh fails
    """
    try:
        creds.refresh(Request())

        # Verify we got a valid new token
        if not creds.token:
            logger.error("Refresh returned empty token for user %s", user_id)
            return None

        # Update stored credentials with new tokens
        stored.encrypted_access_token = encrypt_token(creds.token)
        stored.token_expiry = creds.expiry
        if stored.token_expiry and stored.token_expiry.tzinfo is None:
            stored.token_expiry = stored.token_expiry.replace(tzinfo=timezone.utc)

        db_session.add(stored)
        db_session.commit()

        logger.info("Refreshed and saved token for user %s", user_id)
        return creds

    except Exception as e:
        logger.error("Failed to refresh token for user %s: %s", user_id, e)
        return None


def get_credentials_for_background_task(
    db_session: Session,
    user_id: str
) -> Optional[Credentials]:
    """Get credentials for background tasks with fallback to session.

    Priority:
    1. Load from DB (email_sync type) - preferred for background tasks
    2. Load from DB (primary type) - fallback if email_sync not configured
    3. Parse from session JSON - last resort fallback

    Args:
        db_session: Database session
        user_id: User's unique ID
        session_creds_json: Optional session credentials JSON for fallback

    Returns:
        Credentials object or None
    """

    from db.users import Users
    from utils.billing_utils import is_premium_eligible
    
    user = db_session.get(Users, user_id)
    should_auto_refresh = is_premium_eligible(db_session, user) if user else False

    # Try email_sync credentials first (preferred for background email tasks)
    creds = load_credentials(db_session, user_id, "email_sync", auto_refresh=should_auto_refresh)
    if creds:
        logger.info("Using DB email_sync credentials for user %s", user_id)
        return creds

    # Try primary credentials
    creds = load_credentials(db_session, user_id, "primary", auto_refresh=should_auto_refresh)
    if creds:
        logger.info("Using DB primary credentials for user %s", user_id)
        return creds

    logger.error("No credentials available for user %s", user_id)
    return None


def delete_credentials(
    db_session: Session,
    user_id: str,
    credential_type: Optional[str] = None,
) -> bool:
    """Delete stored credentials (e.g., on logout or account deletion).

    Args:
        db_session: Database session
        user_id: User's unique ID
        credential_type: If specified, delete only that type; otherwise delete all

    Returns:
        True if any credentials were deleted
    """
    try:
        query = select(OAuthCredentials).where(OAuthCredentials.user_id == user_id)
        if credential_type:
            query = query.where(OAuthCredentials.credential_type == credential_type)

        creds = db_session.exec(query).all()
        for cred in creds:
            db_session.delete(cred)

        db_session.commit()
        logger.info("Deleted %d credential(s) for user %s", len(creds), user_id)
        return len(creds) > 0

    except Exception as e:
        logger.error("Failed to delete credentials for user %s: %s", user_id, e)
        db_session.rollback()
        return False
