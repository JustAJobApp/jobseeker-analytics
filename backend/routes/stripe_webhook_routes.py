import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Request, HTTPException, Header
from sqlmodel import select
import stripe
from slowapi import Limiter
from slowapi.util import get_remote_address

from db.users import Users
from db.payments import Payments
from utils.config_utils import get_settings, get_stripe_key
from utils.billing_utils import (
    upgrade_user_to_premium,
    downgrade_user_from_premium,
    PREMIUM_MONTHLY_PRICE_CENTS,
)
import database

settings = get_settings()
logger = logging.getLogger(__name__)
router = APIRouter()
limiter = Limiter(key_func=get_remote_address)


@router.post("/stripe/webhook")
@limiter.limit("100/minute")
async def stripe_webhook(
    request: Request, stripe_signature: str = Header(None, alias="Stripe-Signature")
):
    """Handle Stripe webhook events."""
    if not stripe_signature:
        logger.error("Missing Stripe-Signature header")
        raise HTTPException(status_code=400, detail="Missing signature header")

    get_stripe_key()
    payload = await request.body()

    try:
        event = stripe.Webhook.construct_event(
            payload, stripe_signature, settings.STRIPE_WEBHOOK_SECRET
        )
    except ValueError as e:
        logger.error(f"Invalid payload: {e}")
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError as e:
        logger.error(f"Invalid signature: {e}")
        raise HTTPException(status_code=400, detail="Invalid signature")

    logger.info(f"Received Stripe webhook event: {event['type']}")

    # Handle checkout.session.completed
    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        metadata = session.get("metadata", {})
        user_id = metadata.get("user_id")
        checkout_session_id = session.get("id")

        logger.info(
            f"checkout.session.completed - user_id: {user_id}, subscription: {session.get('subscription')}"
        )

        if not user_id:
            logger.error(f"Missing user_id in checkout session: {checkout_session_id}")
            return {"status": "error", "message": "Missing user_id"}

        # Reject sessions where payment was not collected
        payment_status = session.get("payment_status")
        if payment_status != "paid":
            logger.warning(
                f"checkout.session.completed with payment_status={payment_status!r} "
                f"for user {user_id} — skipping"
            )
            return {"status": "success", "message": "No payment collected"}

        with database.get_session() as db_session:
            # Idempotency check: skip if we've already processed this checkout session
            if checkout_session_id:
                existing = db_session.exec(
                    select(Payments).where(
                        Payments.stripe_checkout_session_id == checkout_session_id
                    )
                ).first()
                if existing:
                    logger.info(
                        f"Duplicate webhook for checkout session {checkout_session_id}, skipping"
                    )
                    return {"status": "success", "message": "Already processed"}

            user = db_session.exec(
                select(Users).where(Users.user_id == user_id)
            ).first()
            if user:
                subscription_id = session.get("subscription")
                # Use amount_total from Stripe directly — the source of truth
                amount_cents = session.get("amount_total", 0)

                # Set monthly price and subscription
                user.subscription_price_cents = amount_cents
                user.stripe_subscription_id = subscription_id
                # Update plan field if user is paying $5+/month (unless promo)
                if amount_cents >= PREMIUM_MONTHLY_PRICE_CENTS and user.plan != "promo":
                    user.plan = "paid"

                if not user.subscribed_at:
                    user.subscribed_at = datetime.now(timezone.utc)
                user.total_paid_cents = (user.total_paid_cents or 0) + amount_cents

                if user.onboarding_completed_at is None:
                    user.onboarding_completed_at = datetime.now(timezone.utc)
                db_session.add(user)

                # Record payment with checkout_session_id for idempotency
                payment = Payments(
                    user_id=user_id,
                    stripe_checkout_session_id=checkout_session_id,
                    stripe_subscription_id=subscription_id,
                    amount_cents=amount_cents,
                    is_recurring=True,
                    status="completed",
                    trigger_type=metadata.get("trigger_type"),
                )
                db_session.add(payment)
                db_session.commit()

                # Upgrade to premium tier if $5+/month
                if amount_cents >= PREMIUM_MONTHLY_PRICE_CENTS:
                    upgrade_user_to_premium(db_session, user_id)

                logger.info(
                    f"User {user_id} subscribed at ${amount_cents / 100:.2f}/month"
                )
            else:
                logger.error(f"User {user_id} not found for checkout session")

    # Handle invoice.paid for recurring monthly renewals
    elif event["type"] == "invoice.paid":
        invoice = event["data"]["object"]
        subscription_id = invoice.get("subscription")
        amount_paid = invoice.get("amount_paid", 0)
        payment_intent_id = invoice.get("payment_intent")

        # Skip the first invoice (already handled by checkout.session.completed)
        billing_reason = invoice.get("billing_reason")
        if billing_reason == "subscription_create":
            logger.info(f"Skipping initial invoice for subscription {subscription_id}")
            return {"status": "success"}

        if subscription_id and amount_paid > 0:
            with database.get_session() as db_session:
                # Idempotency check
                if payment_intent_id:
                    existing = db_session.exec(
                        select(Payments).where(
                            Payments.stripe_checkout_session_id == payment_intent_id
                        )
                    ).first()
                    if existing:
                        logger.info(
                            f"Duplicate invoice webhook for payment_intent {payment_intent_id}, skipping"
                        )
                        return {"status": "success", "message": "Already processed"}

                user = db_session.exec(
                    select(Users).where(Users.stripe_subscription_id == subscription_id)
                ).first()

                if user:
                    user.total_paid_cents = (user.total_paid_cents or 0) + amount_paid
                    db_session.add(user)

                    payment = Payments(
                        user_id=user.user_id,
                        stripe_checkout_session_id=payment_intent_id,
                        stripe_subscription_id=subscription_id,
                        amount_cents=amount_paid,
                        is_recurring=True,
                        status="completed",
                    )
                    db_session.add(payment)
                    db_session.commit()

                    logger.info(
                        f"Renewal payment recorded for user {user.user_id}: ${amount_paid / 100:.2f}"
                    )

    # Handle subscription cancellation
    elif event["type"] == "customer.subscription.deleted":
        subscription = event["data"]["object"]
        subscription_id = subscription["id"]

        with database.get_session() as db_session:
            user = db_session.exec(
                select(Users).where(Users.stripe_subscription_id == subscription_id)
            ).first()

            if user:
                user.subscription_price_cents = 0
                user.stripe_subscription_id = None
                # Reset plan to free (unless promo)
                if user.plan != "promo":
                    user.plan = "free"
                db_session.add(user)
                db_session.commit()

                downgrade_user_from_premium(db_session, user.user_id)

                logger.info(f"Subscription cancelled for user {user.user_id}")

    # Handle subscription price changes from Stripe dashboard or API
    elif event["type"] == "customer.subscription.updated":
        subscription = event["data"]["object"]
        subscription_id = subscription["id"]

        # Get the new amount from the subscription items
        items = subscription.get("items", {}).get("data", [])
        if items:
            new_amount = items[0].get("price", {}).get("unit_amount", 0)

            with database.get_session() as db_session:
                user = db_session.exec(
                    select(Users).where(Users.stripe_subscription_id == subscription_id)
                ).first()

                if user and new_amount > 0:
                    old_amount = user.subscription_price_cents or 0
                    user.subscription_price_cents = new_amount
                    if user.plan != "promo":
                        if new_amount >= PREMIUM_MONTHLY_PRICE_CENTS:
                            user.plan = "paid"
                        else:
                            user.plan = "free"
                    db_session.add(user)
                    db_session.commit()

                    # Upgrade or downgrade based on new price
                    if (
                        new_amount >= PREMIUM_MONTHLY_PRICE_CENTS
                        and old_amount < PREMIUM_MONTHLY_PRICE_CENTS
                    ):
                        upgrade_user_to_premium(db_session, user.user_id)
                    elif (
                        new_amount < PREMIUM_MONTHLY_PRICE_CENTS
                        and old_amount >= PREMIUM_MONTHLY_PRICE_CENTS
                    ):
                        downgrade_user_from_premium(db_session, user.user_id)

                    logger.info(
                        f"Subscription price updated for user {user.user_id}: ${new_amount / 100:.2f}/mo"
                    )

    # Handle customer.created
    elif event["type"] == "customer.created":
        customer = event["data"]["object"]
        stripe_customer_id = customer.get("id")
        user_id = customer.get("metadata", {}).get("user_id")

        if user_id and stripe_customer_id:
            with database.get_session() as db_session:
                user = db_session.exec(
                    select(Users).where(Users.user_id == user_id)
                ).first()

                if user:
                    if user.stripe_customer_id != stripe_customer_id:
                        user.stripe_customer_id = stripe_customer_id
                        db_session.add(user)
                        db_session.commit()
                        logger.info(f"Updated user {user_id} with new Stripe Customer ID: {stripe_customer_id}")
                else:
                    logger.error(f"User {user_id} not found for created customer {stripe_customer_id}")
    else:
        logger.error("Not responding to event type %s", event["type"])
    return {"status": "success"}
