import logging
from typing import Optional

from fastapi import APIRouter, Depends, Request, HTTPException
from pydantic import BaseModel
from sqlmodel import select
import stripe

from db.users import Users
from session.session_layer import validate_session
from utils.config_utils import get_settings, get_stripe_key
import database
from slowapi import Limiter
from slowapi.util import get_remote_address

settings = get_settings()
logger = logging.getLogger(__name__)
router = APIRouter()
limiter = Limiter(key_func=get_remote_address)

# Fixed premium price - no user-supplied amounts allowed
PREMIUM_AMOUNT_CENTS = 500  # $5/month


# Request/Response models
class ValidatePromoRequest(BaseModel):
    code: str


class CheckoutRequest(BaseModel):
    trigger_type: Optional[str] = None


@router.post("/payment/validate-promo")
@limiter.limit("10/minute")
async def validate_promo_code(
    request: Request,
    body: ValidatePromoRequest,
    user_id: str = Depends(validate_session)
):
    """Validate a Stripe promotion code. Returns {valid: bool}."""
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    get_stripe_key()

    code = body.code.strip().upper()
    if not code:
        return {"valid": False}

    try:
        codes = stripe.PromotionCode.list(code=code, active=True, limit=1)
        valid = len(codes.data) > 0
        logger.info(f"Promo code validation for user {user_id}: code={code} valid={valid}")
        return {"valid": valid}
    except stripe.error.StripeError as e:
        logger.error(f"Stripe error validating promo code: {e}")
        raise HTTPException(status_code=500, detail="Failed to validate promo code")


@router.post("/payment/checkout")
@limiter.limit("10/minute")
async def create_checkout(
    request: Request,
    body: CheckoutRequest,
    db_session: database.DBSession,
    user_id: str = Depends(validate_session)
):
    """Create Stripe checkout session for premium subscription ($5/month)."""
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    get_stripe_key()

    user = db_session.exec(select(Users).where(Users.user_id == user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Use fixed premium amount - ignore any user-supplied amount
    amount_cents = PREMIUM_AMOUNT_CENTS

    try:
        # Create or get Stripe customer
        if not user.stripe_customer_id:
            customer = stripe.Customer.create(
                email=user.user_email,
                metadata={"user_id": user_id}
            )
            user.stripe_customer_id = customer.id
            db_session.add(user)
            db_session.commit()

        checkout_session = stripe.checkout.Session.create(
            customer=user.stripe_customer_id,
            mode="subscription",
            line_items=[{
                "price_data": {
                    "currency": "usd",
                    "unit_amount": amount_cents,
                    "recurring": {"interval": "month"},
                    "product_data": {"name": "JustAJobApp Monthly Contribution"}
                },
                "quantity": 1
            }],
            success_url=f"{settings.APP_URL}/payment/thank-you?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{settings.APP_URL}/dashboard",
            metadata={
                "user_id": user_id,
                "amount_cents": str(amount_cents),
                "trigger_type": body.trigger_type or "manual",
            },
            subscription_data={
                "metadata": {
                    "user_id": user_id,
                    "amount_cents": str(amount_cents)
                }
            }
        )

        logger.info(f"Created checkout session {checkout_session.id} for user {user_id}, amount: {amount_cents}")
        return {"checkout_url": checkout_session.url, "session_id": checkout_session.id}

    except stripe.error.StripeError as e:
        logger.error(f"Stripe error creating checkout session: {e}")
        raise HTTPException(status_code=500, detail="Failed to create checkout session")


@router.post("/payment/cancel")
@limiter.limit("5/minute")
async def cancel_contribution(
    request: Request,
    db_session: database.DBSession,
    user_id: str = Depends(validate_session)
):
    """Cancel contribution subscription."""
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    get_stripe_key()

    user = db_session.exec(select(Users).where(Users.user_id == user_id)).first()
    if not user or not user.stripe_subscription_id:
        raise HTTPException(status_code=400, detail="No active subscription")

    try:
        # Verify subscription ownership before cancelling
        subscription = stripe.Subscription.retrieve(user.stripe_subscription_id)
        subscription_user_id = subscription.get("metadata", {}).get("user_id")
        if subscription_user_id != user_id:
            logger.error(f"Subscription ownership mismatch: expected {user_id}, got {subscription_user_id}")
            raise HTTPException(status_code=403, detail="Subscription does not belong to user")

        # Cancel at period end so user keeps benefits until billing cycle ends
        updated_subscription = stripe.Subscription.modify(
            user.stripe_subscription_id,
            cancel_at_period_end=True
        )

        # Don't clear monthly_contribution_cents yet - webhook will handle that
        # when subscription actually ends
        period_end = updated_subscription.get("cancel_at")

        logger.info(f"Contribution scheduled for cancellation for user {user_id}, ends at {period_end}")
        return {
            "cancelled": True,
            "cancel_at_period_end": True,
            "period_end_timestamp": period_end
        }

    except stripe.error.StripeError as e:
        logger.error(f"Stripe cancellation error: {e}")
        raise HTTPException(status_code=500, detail="Could not cancel subscription")
