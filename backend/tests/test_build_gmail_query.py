"""Unit tests for build_gmail_query.

build_gmail_query is a pure function — no DB or HTTP fixtures needed.
The scenarios tested mirror the four real call sites:
  - Incremental scan (last_updated set, start_date not recently updated)
  - Onboarding full scan (no last_updated, start_date_updated False)
  - Free user (start date capped to 30 days ago, scan_end_date = today)
  - Premium user (start date > 30 days ago, no upper bound)
"""

import re
from datetime import datetime, timedelta, timezone

from routes.email_routes import build_gmail_query

EXPECTED_FIXED_CLAUSES = ["-from:me", "-in:sent", "AND ("]


def _assert_well_formed(query: str) -> None:
    """Every query must have the fixed exclusion clauses and base filter."""
    for clause in EXPECTED_FIXED_CLAUSES:
        assert clause in query, f"Missing '{clause}' in query: {query}"
    assert query.count("after:") == 1, f"Expected exactly one after: clause, got: {query}"


# ---------------------------------------------------------------------------
# Incremental scan
# ---------------------------------------------------------------------------

def test_incremental_scan_uses_last_updated_as_sole_after_date():
    """Incremental scan must produce exactly one after: clause using last_updated,
    not a double after: from prepending QUERY_APPLIED_EMAIL_FILTER."""
    last_updated = datetime(2026, 3, 1, tzinfo=timezone.utc)

    query = build_gmail_query(
        last_updated=last_updated,
        start_date_updated=False,
        start_date="2025/01/01",
        scan_end_date=None,
    )

    _assert_well_formed(query)
    assert "after:2026/03/01" in query
    assert "before:" not in query


def test_incremental_scan_with_end_date():
    last_updated = datetime(2026, 3, 1, tzinfo=timezone.utc)
    scan_end = datetime(2026, 3, 28, tzinfo=timezone.utc)

    query = build_gmail_query(
        last_updated=last_updated,
        start_date_updated=False,
        start_date=None,
        scan_end_date=scan_end,
    )

    _assert_well_formed(query)
    assert "after:2026/03/01" in query
    assert "before:2026/03/28" in query


# ---------------------------------------------------------------------------
# Onboarding — no prior emails, start_date_updated not set yet
# ---------------------------------------------------------------------------

def test_onboarding_full_scan_from_start_date():
    """During onboarding last_updated is None so a full scan from start_date runs."""
    query = build_gmail_query(
        last_updated=None,
        start_date_updated=False,
        start_date="2026/01/15",
        scan_end_date=None,
    )

    _assert_well_formed(query)
    assert "after:2026/01/15" in query
    assert "before:" not in query


def test_onboarding_with_scan_end_date():
    query = build_gmail_query(
        last_updated=None,
        start_date_updated=False,
        start_date="2026/01/15",
        scan_end_date=datetime(2026, 3, 28, tzinfo=timezone.utc),
    )

    _assert_well_formed(query)
    assert "after:2026/01/15" in query
    assert "before:2026/03/28" in query


# ---------------------------------------------------------------------------
# Free user — start date capped to last 30 days, scan_end_date = today
# ---------------------------------------------------------------------------

def _extract_after_date(query: str) -> datetime:
    match = re.search(r"after:(\d{4}/\d{2}/\d{2})", query)
    assert match, f"No after: date found in query: {query}"
    return datetime.strptime(match.group(1), "%Y/%m/%d").replace(tzinfo=timezone.utc)


def test_free_user_query_does_not_reach_beyond_30_days():
    """Free users have their start date capped at 30 days ago by the caller.
    Verify the resulting query's after: date stays within that window."""
    now = datetime.now(timezone.utc)
    thirty_days_ago = now - timedelta(days=30)
    start_date_str = thirty_days_ago.strftime("%Y/%m/%d")

    query = build_gmail_query(
        last_updated=None,
        start_date_updated=True,
        start_date=start_date_str,
        scan_end_date=now,
    )

    _assert_well_formed(query)
    after_date = _extract_after_date(query)
    # Allow one day of slack for timezone rounding
    assert after_date >= thirty_days_ago - timedelta(days=1), (
        "Free user query must not reach further back than 30 days"
    )
    assert f"before:{now.strftime('%Y/%m/%d')}" in query


def test_free_user_query_is_bounded_on_both_ends():
    """Free user query must have both after: and before: clauses."""
    now = datetime.now(timezone.utc)
    start_date_str = (now - timedelta(days=30)).strftime("%Y/%m/%d")

    query = build_gmail_query(
        last_updated=None,
        start_date_updated=True,
        start_date=start_date_str,
        scan_end_date=now,
    )

    _assert_well_formed(query)
    assert "after:" in query
    assert "before:" in query


# ---------------------------------------------------------------------------
# Premium user — start date can go further back, no upper cap required
# ---------------------------------------------------------------------------

def test_premium_user_can_query_beyond_30_days():
    """Premium users can request a start date more than 30 days ago."""
    now = datetime.now(timezone.utc)
    ninety_days_ago = now - timedelta(days=90)
    start_date_str = ninety_days_ago.strftime("%Y/%m/%d")

    query = build_gmail_query(
        last_updated=None,
        start_date_updated=True,
        start_date=start_date_str,
        scan_end_date=None,
    )

    _assert_well_formed(query)
    after_date = _extract_after_date(query)
    thirty_days_ago = now - timedelta(days=30)
    assert after_date < thirty_days_ago, (
        "Premium user query should be able to reach further back than 30 days"
    )
    assert "before:" not in query


def test_premium_user_with_end_date():
    now = datetime.now(timezone.utc)
    ninety_days_ago = now - timedelta(days=90)

    query = build_gmail_query(
        last_updated=None,
        start_date_updated=True,
        start_date=ninety_days_ago.strftime("%Y/%m/%d"),
        scan_end_date=now,
    )

    _assert_well_formed(query)
    after_date = _extract_after_date(query)
    assert after_date < now - timedelta(days=30)
    assert f"before:{now.strftime('%Y/%m/%d')}" in query
