"""Canonical definition of free vs pro tier limits.

All tier-differentiated behavior should reference constants from this module
so limits can be changed in one place.

Free tier: users with monthly_price_cents == 0 (and not a coach/coach-client).
Pro tier:  users with an active $5+/month subscription, coaches, or active coach-clients.
           Determined by is_premium_eligible() in billing_utils.py.
"""

# ---------------------------------------------------------------------------
# History window
# ---------------------------------------------------------------------------

# Free users see only this many days of email history in the dashboard and CSV.
# Older emails are retained in the database and become visible on upgrade.
FREE_HISTORY_DAYS: int = 30

# ---------------------------------------------------------------------------
# Email scan (manual "Refresh" button)
# ---------------------------------------------------------------------------

# Maximum number of emails processed in a single manual scan session.
# Same for both tiers; controlled by settings.batch_size_by_env (env-specific).
# Pro users are not currently given a higher per-scan limit, but this is where
# you would add that differentiation.
#
# FREE_SCAN_LIMIT = 50      # (future: lower limit for free users)
# PRO_SCAN_LIMIT  = 10000   # (future: match settings.BATCH_SIZE for pro users)

# How often a user may trigger a manual scan (enforced on the frontend via
# should_rescan and on the backend via the processed_emails >= batch_size check).
MANUAL_SCAN_COOLDOWN_HOURS: int = 24  # applies to both tiers

# ---------------------------------------------------------------------------
# Background / scheduled sync ("Always Open")
# ---------------------------------------------------------------------------

# Free users rely on manual scans only.
# Pro users receive automated background sync on this schedule (UTC hours).
PRO_BACKGROUND_SYNC_HOURS: tuple[int, ...] = (3, 15)  # 3 AM and 3 PM UTC

# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------

# CSV is available to both tiers; free users export their 30-day window because
# query_emails() already applies the FREE_HISTORY_DAYS filter before the CSV
# route calls it. No separate limit needed here.

# ---------------------------------------------------------------------------
# Manual application entries
# ---------------------------------------------------------------------------

# No limit on manually added applications for either tier at this time.
# FREE_MANUAL_APP_LIMIT = None
# PRO_MANUAL_APP_LIMIT  = None

# ---------------------------------------------------------------------------
# Monthly email processing cap
# ---------------------------------------------------------------------------

# Maximum emails a user may have processed in a single calendar month.
# Counter resets on the 1st of each month. Scans that hit the cap return
# early with CANCELLED status.
FREE_MONTHLY_EMAIL_CAP: int = 500
PRO_MONTHLY_EMAIL_CAP: int = 5000

# ---------------------------------------------------------------------------
# Summary (for documentation / settings UI)
# ---------------------------------------------------------------------------

FREE_TIER_FEATURES: dict = {
    "history_days": FREE_HISTORY_DAYS,
    "background_sync": False,
    "csv_export": True,
    "manual_scan": True,
    "manual_scan_cooldown_hours": MANUAL_SCAN_COOLDOWN_HOURS,
    "monthly_email_cap": FREE_MONTHLY_EMAIL_CAP,
}

PRO_TIER_FEATURES: dict = {
    "history_days": None,           # unlimited
    "background_sync": True,
    "csv_export": True,
    "manual_scan": True,
    "manual_scan_cooldown_hours": MANUAL_SCAN_COOLDOWN_HOURS,
    "monthly_email_cap": PRO_MONTHLY_EMAIL_CAP,
}
