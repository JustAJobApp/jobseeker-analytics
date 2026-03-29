import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Request, HTTPException
from pydantic import BaseModel
from sqlmodel import select

from db.users import Users
from session.session_layer import validate_session
from utils.config_utils import get_settings
import database
from slowapi import Limiter
from slowapi.util import get_remote_address

settings = get_settings()
logger = logging.getLogger(__name__)
router = APIRouter()
limiter = Limiter(key_func=get_remote_address)


class OnboardingStatusResponse(BaseModel):
    has_completed_onboarding: bool
    has_email_sync_configured: bool
    sync_email_address: Optional[str]
    role: str
    plan: str


class SetRoleRequest(BaseModel):
    role: str  # 'jobseeker' | 'coach'


class ApplyPromoRequest(BaseModel):
    code: str


@router.get("/api/users/onboarding-status", response_model=OnboardingStatusResponse)
@limiter.limit("10/minute")
async def get_onboarding_status(
    request: Request,
    db_session: database.DBSession,
    user_id: str = Depends(validate_session)
):
    """Get the current user's onboarding status."""
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = db_session.exec(select(Users).where(Users.user_id == user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return OnboardingStatusResponse(
        has_completed_onboarding=user.onboarding_completed_at is not None,
        has_email_sync_configured=user.has_email_sync_configured,
        sync_email_address=user.sync_email_address,
        role=user.role,
        plan=user.plan,
    )


@router.post("/api/onboarding/role")
@limiter.limit("5/minute")
async def set_onboarding_role(
    request: Request,
    body: SetRoleRequest,
    db_session: database.DBSession,
    user_id: str = Depends(validate_session)
):
    """Set user role during onboarding step 1."""
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    if body.role not in ("jobseeker", "coach"):
        raise HTTPException(status_code=400, detail="role must be 'jobseeker' or 'coach'")

    user = db_session.exec(select(Users).where(Users.user_id == user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.role = body.role
    db_session.add(user)
    db_session.commit()

    logger.info(f"User {user_id} set role to {body.role}")
    return {"role": user.role}


@router.post("/api/onboarding/apply-promo")
@limiter.limit("10/minute")
async def apply_promo(
    request: Request,
    body: ApplyPromoRequest,
    db_session: database.DBSession,
    user_id: str = Depends(validate_session)
):
    """Validate a Stripe promo code and apply it to the user's account.

    Must be called BEFORE PUT /settings/start-date so the backfill uses the
    correct (full-range) scan scope for promo users.
    """
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    import stripe
    from utils.config_utils import get_stripe_key
    get_stripe_key()

    code = body.code.strip().upper()
    if not code:
        return {"valid": False, "applied": False}

    try:
        codes = stripe.PromotionCode.list(code=code, active=True, limit=1)
        valid = len(codes.data) > 0
    except stripe.error.StripeError as e:
        logger.error(f"Stripe error validating promo code for user {user_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to validate promo code")

    if not valid:
        return {"valid": False, "applied": False}

    user = db_session.exec(select(Users).where(Users.user_id == user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.plan = "promo"
    user.promo_code_used = code
    user.sync_tier = "premium"
    db_session.add(user)
    db_session.commit()

    logger.info(f"User {user_id} applied promo code {code}")
    return {"valid": True, "applied": True}


@router.post("/api/users/complete-onboarding")
@limiter.limit("5/minute")
async def complete_onboarding(
    request: Request,
    db_session: database.DBSession,
    user_id: str = Depends(validate_session)
):
    """Mark onboarding as complete. Promo codes must be applied via /api/onboarding/apply-promo first."""
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = db_session.exec(select(Users).where(Users.user_id == user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.onboarding_completed_at is not None:
        raise HTTPException(status_code=400, detail="Onboarding already completed")

    user.onboarding_completed_at = datetime.now(timezone.utc)
    db_session.add(user)
    db_session.commit()

    logger.info(f"User {user_id} completed onboarding (plan={user.plan})")
    return {"message": "Onboarding completed", "plan": user.plan}
