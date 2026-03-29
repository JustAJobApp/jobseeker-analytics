import logging
from datetime import date
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from typing import Optional
from slowapi import Limiter
from slowapi.util import get_remote_address

import database
from db.users import Users
from session.session_layer import validate_session, clear_session
from utils.credential_service import load_credentials
from utils.billing_utils import get_premium_reason
from utils.config_utils import get_stripe_key
import stripe

# Logger setup
logger = logging.getLogger(__name__)

limiter = Limiter(key_func=get_remote_address)

# FastAPI router for user routes
router = APIRouter()


class PremiumStatusResponse(BaseModel):
    """Unified premium status for frontend settings modal."""

    is_premium: bool
    premium_reason: Optional[str]  # "coach", "coach_client", "paid", or None
    subscription_price_cents: int
    has_active_subscription: bool
    has_valid_credentials: bool
    last_background_sync_at: Optional[str]
    subscribed_at: Optional[str]
    cancel_at_period_end: bool = False
    subscription_ends_at: Optional[int] = None  # Unix timestamp when cancelled
    subscription_renews_at: Optional[int] = None  # Unix timestamp for next renewal
    subscription_interval: Optional[str] = None  # "month" or "year"
    emails_processed_this_month: int = 0
    monthly_email_cap: int
    monthly_reset_date: Optional[str] = None  # ISO date of next reset (1st of next month)
    fetch_order: str = "recent_first"
    scan_end_date: Optional[str] = None  # ISO datetime string or None


@router.get("/settings/premium-status")
@limiter.limit("20/minute")
async def get_premium_status(
    request: Request,
    db_session: database.DBSession,
    user_id: str = Depends(validate_session),
) -> PremiumStatusResponse:
    """Get unified premium status for settings modal.

    Combines subscription info and background sync status in one endpoint.
    """
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = db_session.get(Users, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Check if user has valid OAuth credentials stored
    creds = load_credentials(db_session, user_id, "email_sync", auto_refresh=False)
    if not creds:
        creds = load_credentials(db_session, user_id, "primary", auto_refresh=False)
    has_valid_credentials = creds is not None

    # Get premium reason
    premium_reason = get_premium_reason(db_session, user)
    is_premium = premium_reason is not None

    # Check Stripe subscription status for cancellation and renewal info
    cancel_at_period_end = False
    subscription_ends_at = None
    subscription_renews_at = None
    subscription_interval = None
    if user.stripe_subscription_id:
        try:
            get_stripe_key()
            subscription = stripe.Subscription.retrieve(user.stripe_subscription_id)
            cancel_at_period_end = subscription.get("cancel_at_period_end", False)
            if cancel_at_period_end:
                subscription_ends_at = subscription.get("cancel_at")
            # Get renewal date and interval from subscription items
            items = subscription.get("items", {})
            items_data = items.get("data", [])
            if items_data:
                subscription_renews_at = items_data[0].get("current_period_end")
                subscription_interval = items_data[0].get("price", {}).get("recurring", {}).get("interval")
        except stripe.error.StripeError as e:
            logger.warning(f"Failed to fetch subscription status: {e}")

    from utils.billing_utils import get_monthly_email_cap, reset_monthly_counter_if_needed

    # Reset counter if we've rolled into a new calendar month, then persist
    user = reset_monthly_counter_if_needed(user)
    db_session.add(user)
    db_session.commit()

    monthly_cap = get_monthly_email_cap(db_session, user)
    emails_processed = user.emails_processed_this_month or 0

    # Next reset = 1st of next month
    today = date.today()
    if today.month == 12:
        next_reset = date(today.year + 1, 1, 1)
    else:
        next_reset = date(today.year, today.month + 1, 1)

    fetch_order = user.fetch_order or "recent_first"
    scan_end_date_str = user.scan_end_date.isoformat() if user.scan_end_date else None

    return PremiumStatusResponse(
        is_premium=is_premium,
        premium_reason=premium_reason,
        subscription_price_cents=user.subscription_price_cents,
        has_active_subscription=user.stripe_subscription_id is not None,
        has_valid_credentials=has_valid_credentials,
        last_background_sync_at=(
            user.last_background_sync_at.isoformat()
            if user.last_background_sync_at
            else None
        ),
        subscribed_at=(
            user.subscribed_at.isoformat()
            if user.subscribed_at
            else None
        ),
        cancel_at_period_end=cancel_at_period_end,
        subscription_ends_at=subscription_ends_at,
        subscription_renews_at=subscription_renews_at,
        subscription_interval=subscription_interval,
        emails_processed_this_month=emails_processed,
        monthly_email_cap=monthly_cap,
        monthly_reset_date=next_reset.isoformat(),
        fetch_order=fetch_order,
        scan_end_date=scan_end_date_str,
    )


@router.delete("/api/users/me")
@limiter.limit("3/minute")
async def delete_account(
    request: Request,
    db_session: database.DBSession,
    user_id: str = Depends(validate_session),
):
    """Permanently delete the user's account and all associated data.

    This deletes:
    - All user emails
    - All task runs
    - All OAuth credentials
    - The user record itself
    - Revokes OAuth tokens where possible
    """
    from sqlmodel import select
    from db.user_emails import UserEmails
    from db.processing_tasks import TaskRuns
    from db.oauth_credentials import OAuthCredentials
    from db.payments import Payments
    from fastapi.responses import RedirectResponse
    from utils.config_utils import get_settings

    settings = get_settings()

    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = db_session.get(Users, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    logger.info(f"Beginning account deletion for user {user_id}")

    # Cancel Stripe subscription if exists
    if user.stripe_subscription_id:
        try:
            get_stripe_key()
            stripe.Subscription.delete(user.stripe_subscription_id)
            logger.info(f"Cancelled Stripe subscription for user {user_id}")
        except stripe.error.StripeError as e:
            logger.warning(f"Failed to cancel Stripe subscription for user {user_id}: {e}")

    # Revoke OAuth tokens
    all_creds = db_session.exec(
        select(OAuthCredentials).where(OAuthCredentials.user_id == user_id)
    ).all()

    for cred_record in all_creds:
        try:
            creds = load_credentials(db_session, user_id, credential_type=cred_record.credential_type, auto_refresh=False)
            if creds and creds.token:
                import httplib2
                h = httplib2.Http()
                h.request(
                    f"https://oauth2.googleapis.com/revoke?token={creds.token}",
                    method="POST",
                    headers={"Content-Type": "application/x-www-form-urlencoded"}
                )
                logger.info(f"Revoked {cred_record.credential_type} token for user {user_id}")
        except Exception as e:
            logger.warning(f"Failed to revoke {cred_record.credential_type} token for user {user_id}: {e}")

    # Delete all user emails
    emails = db_session.exec(
        select(UserEmails).where(UserEmails.user_id == user_id)
    ).all()
    for email in emails:
        db_session.delete(email)
    logger.info(f"Deleted {len(emails)} emails for user {user_id}")

    # Delete all task runs
    tasks = db_session.exec(
        select(TaskRuns).where(TaskRuns.user_id == user_id)
    ).all()
    for task in tasks:
        db_session.delete(task)
    logger.info(f"Deleted {len(tasks)} task runs for user {user_id}")

    # Delete all OAuth credentials
    for cred_record in all_creds:
        db_session.delete(cred_record)
    logger.info(f"Deleted {len(all_creds)} OAuth credentials for user {user_id}")

    # Delete payment records
    payments = db_session.exec(
        select(Payments).where(Payments.user_id == user_id)
    ).all()
    for payment in payments:
        db_session.delete(payment)
    logger.info(f"Deleted {len(payments)} payment records for user {user_id}")

    # Delete the user record
    db_session.delete(user)
    db_session.commit()
    logger.info(f"Account deletion complete for user {user_id}")

    # Clear the session
    response = RedirectResponse(url=f"{settings.APP_URL}", status_code=303)
    clear_session(request, response)

    return {"message": "Account deleted successfully"}
