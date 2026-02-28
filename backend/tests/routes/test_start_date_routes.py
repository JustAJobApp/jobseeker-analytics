# backend/tests/routes/test_start_date_routes.py
from unittest import mock
from sqlmodel import Session
from google.oauth2.credentials import Credentials

def test_set_start_date(db_session: Session, logged_in_client, logged_in_user):
    """
    Test setting the start date for a user who was manually added.
    """

    # 1. Manually create user with no start_date
    db_session.add(logged_in_user)
    db_session.commit()
    db_session.refresh(logged_in_user)
    assert logged_in_user.start_date is None

    start_date_str = "2024-05-10"

    # Mock load_credentials instead of the session cookie
    mock_creds = Credentials(token="mock_token", refresh_token="mock_refresh")

    with mock.patch("routes.start_date_routes.load_credentials", return_value=mock_creds):
        response = logged_in_client.put(
            "/settings/start-date",
            json={"preset": "custom", "custom_date": start_date_str},
        )

    assert response.status_code == 200
    data = response.json()
    assert "start_date" in data
    assert data["start_date"].startswith(start_date_str)

    # 3. Verify the date in the database
    db_session.refresh(logged_in_user)
    assert logged_in_user.start_date is not None
    assert logged_in_user.start_date.strftime("%Y-%m-%d") == start_date_str
