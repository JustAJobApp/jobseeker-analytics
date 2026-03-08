from datetime import datetime, timedelta, timezone
from db.utils.user_utils import user_exists, add_user, get_last_email_date
from db.users import Users
from db.user_emails import UserEmails
from unittest.mock import MagicMock

def test_get_last_email_date_returns_none_for_no_emails(db_session):
    """Verify that get_last_email_date returns None if no records exist."""
    user_id = "test_user_no_emails"
    last_date = get_last_email_date(user_id, db_session)
    assert last_date is None

def test_get_last_email_date_returns_latest_date(db_session, logged_in_user):
    """Verify the max(received_at) is returned correctly for incremental fetching."""
    user_id = logged_in_user.user_id
    date_old = datetime.now(timezone.utc) - timedelta(days=5)
    date_new = datetime.now(timezone.utc) - timedelta(days=1)
    
    # Create email records to simulate historical data
    email1 = UserEmails(id="msg_1", user_id=user_id, received_at=date_old, company_name="Corp A")
    email2 = UserEmails(id="msg_2", user_id=user_id, received_at=date_new, company_name="Corp B")
    db_session.add_all([email1, email2])
    db_session.commit()
    
    last_date = get_last_email_date(user_id, db_session)
    # Ensure the returned date matches the most recent entry
    assert last_date.replace(microsecond=0) == date_new.replace(microsecond=0)

def test_user_exists_returns_correct_attributes(logged_in_user, db_session):
    """Maintain existing behavior: verify that active user data is retrieved correctly."""
    user_object, _ = user_exists(logged_in_user, db_session)
    assert user_object.is_active is True
    assert user_object.user_id == logged_in_user.user_id

def test_inactive_user_attribute_is_returned(inactive_user, db_session):
    """Maintain existing behavior: verify that inactive status is preserved."""
    user_object, _ = user_exists(inactive_user, db_session)
    assert user_object.is_active is False

def test_user_exists_updates_user_id_on_match(db_session):
    """Verify that if email matches but ID differs (OAuth provider change), the ID is updated."""
    email = "identity_match@example.com"
    old_id = "original_google_id"
    new_id = "updated_google_id"
    
    # Seed DB with old ID
    existing = Users(user_id=old_id, user_email=email, is_active=True)
    db_session.add(existing)
    db_session.commit()
    
    # Mock OAuth user with the new ID
    oauth_user = MagicMock(user_id=new_id, user_email=email)
    
    user_obj, _ = user_exists(oauth_user, db_session)
    
    assert user_obj.user_id == new_id
    # Ensure the database record was actually updated
    db_session.expire_all()
    refetched = db_session.get(Users, new_id)
    assert refetched is not None
    assert refetched.user_email == email

def test_add_user_defaults_to_90_day_lookback(db_session):
    """Verify new users get a default start_date of 90 days ago during registration."""
    oauth_user = MagicMock(user_id="new_account_123", user_email="welcome@example.com")
    request = MagicMock(session={})
    
    new_user = add_user(oauth_user, request, db_session)
    
    # The default lookback for account creation is 90 days
    expected_default = (datetime.now(timezone.utc) - timedelta(days=90)).date()
    assert new_user.user_id == "new_account_123"
    assert new_user.start_date.date() == expected_default
    # Verify the date is stored in session for frontend consistency
    assert "start_date" in request.session

def test_add_user_respects_explicit_start_date(db_session):
    """Verify that add_user accepts an explicit start_date if provided."""
    custom_date = datetime.now(timezone.utc) - timedelta(days=7)
    oauth_user = MagicMock(user_id="manual_date_user", user_email="manual@example.com")
    oauth_user.start_date = custom_date
    request = MagicMock(session={})
    
    new_user = add_user(oauth_user, request, db_session)
    
    assert new_user.start_date.date() == custom_date.date()