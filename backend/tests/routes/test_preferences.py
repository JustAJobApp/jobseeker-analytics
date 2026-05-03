"""Tests for /api/email-signup and /settings/email-marketing-consent."""

from datetime import datetime, timezone
from types import SimpleNamespace

from sqlmodel import select

from db.users import Users
from db.utils.user_utils import user_exists


class TestEmailMarketingConsent:
    """PUT /settings/email-marketing-consent — authenticated consent toggle."""

    def test_unauthenticated_returns_401(self, incognito_client):
        resp = incognito_client.put(
            "/settings/email-marketing-consent", json={"consent": True}
        )
        assert resp.status_code == 401

    def test_opt_in_from_false_sets_flag_and_timestamp(
        self, client_factory, logged_in_user
    ):
        client = client_factory(user=logged_in_user)
        assert logged_in_user.email_marketing_consent is False
        assert logged_in_user.email_marketing_consent_at is None

        resp = client.put(
            "/settings/email-marketing-consent", json={"consent": True}
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["email_marketing_consent"] is True
        assert data["email_marketing_consent_at"] is not None

    def test_opt_in_when_already_true_is_noop(
        self, client_factory, logged_in_user, db_session
    ):
        client = client_factory(user=logged_in_user)
        client.put("/settings/email-marketing-consent", json={"consent": True})

        db_session.refresh(logged_in_user)
        original_ts = logged_in_user.email_marketing_consent_at
        assert original_ts is not None

        resp = client.put(
            "/settings/email-marketing-consent", json={"consent": True}
        )

        assert resp.status_code == 200
        db_session.refresh(logged_in_user)
        assert logged_in_user.email_marketing_consent is True
        assert logged_in_user.email_marketing_consent_at == original_ts

    def test_opt_out_nulls_timestamp(
        self, client_factory, logged_in_user, db_session
    ):
        client = client_factory(user=logged_in_user)
        client.put("/settings/email-marketing-consent", json={"consent": True})

        resp = client.put(
            "/settings/email-marketing-consent", json={"consent": False}
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["email_marketing_consent"] is False
        assert data["email_marketing_consent_at"] is None

        db_session.refresh(logged_in_user)
        assert logged_in_user.email_marketing_consent is False
        assert logged_in_user.email_marketing_consent_at is None

    def test_opt_out_when_already_false_is_noop(
        self, client_factory, logged_in_user
    ):
        client = client_factory(user=logged_in_user)

        resp = client.put(
            "/settings/email-marketing-consent", json={"consent": False}
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["email_marketing_consent"] is False
        assert data["email_marketing_consent_at"] is None

    def test_re_opt_in_after_opt_out_uses_new_timestamp(
        self, client_factory, logged_in_user, db_session
    ):
        client = client_factory(user=logged_in_user)

        client.put("/settings/email-marketing-consent", json={"consent": True})
        db_session.refresh(logged_in_user)
        first_ts = logged_in_user.email_marketing_consent_at

        client.put("/settings/email-marketing-consent", json={"consent": False})

        client.put("/settings/email-marketing-consent", json={"consent": True})
        db_session.refresh(logged_in_user)
        second_ts = logged_in_user.email_marketing_consent_at

        assert logged_in_user.email_marketing_consent is True
        assert second_ts is not None
        assert second_ts != first_ts

    def test_me_endpoint_includes_consent(self, client_factory, logged_in_user):
        client = client_factory(user=logged_in_user)
        client.put("/settings/email-marketing-consent", json={"consent": True})

        resp = client.get("/me")
        assert resp.status_code == 200
        assert resp.json()["email_marketing_consent"] is True


class TestEmailSignup:
    """POST /api/email-signup — public landing-page form."""

    def test_invalid_email_returns_400(self, incognito_client):
        resp = incognito_client.post(
            "/api/email-signup", json={"email": "not-an-email"}
        )
        assert resp.status_code == 400

    def test_new_email_creates_lite_user_with_consent(
        self, incognito_client, db_session
    ):
        resp = incognito_client.post(
            "/api/email-signup", json={"email": "lianna@example.com"}
        )
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}

        user = db_session.exec(
            select(Users).where(Users.user_email == "lianna@example.com")
        ).first()
        assert user is not None
        assert user.email_marketing_consent is True
        assert user.email_marketing_consent_at is not None
        assert user.role == ""
        assert user.onboarding_completed_at is None
        assert user.has_email_sync_configured is False

    def test_existing_user_with_consent_false_is_opted_in(
        self, incognito_client, user_factory, db_session
    ):
        existing = user_factory(
            user_id="existing1",
            user_email="existing@example.com",
            role="jobseeker",
        )
        assert existing.email_marketing_consent is False

        resp = incognito_client.post(
            "/api/email-signup", json={"email": "existing@example.com"}
        )
        assert resp.status_code == 200

        db_session.refresh(existing)
        assert existing.email_marketing_consent is True
        assert existing.email_marketing_consent_at is not None
        # Other fields untouched
        assert existing.user_id == "existing1"
        assert existing.role == "jobseeker"

    def test_existing_consenting_user_timestamp_preserved(
        self, incognito_client, user_factory, db_session
    ):
        original_ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
        existing = user_factory(
            user_id="opted",
            user_email="opted@example.com",
            role="jobseeker",
        )
        existing.email_marketing_consent = True
        existing.email_marketing_consent_at = original_ts
        db_session.add(existing)
        db_session.commit()

        resp = incognito_client.post(
            "/api/email-signup", json={"email": "opted@example.com"}
        )
        assert resp.status_code == 200

        db_session.refresh(existing)
        assert existing.email_marketing_consent is True
        assert existing.email_marketing_consent_at == original_ts

    def test_no_duplicate_row_on_repeat_signup(
        self, incognito_client, db_session
    ):
        incognito_client.post(
            "/api/email-signup", json={"email": "twice@example.com"}
        )
        incognito_client.post(
            "/api/email-signup", json={"email": "twice@example.com"}
        )

        rows = db_session.exec(
            select(Users).where(Users.user_email == "twice@example.com")
        ).all()
        assert len(rows) == 1


class TestEmailSignupOAuthReconciliation:
    """The critical end-to-end: lite signup then OAuth merges by email."""

    def test_oauth_after_email_signup_preserves_consent(
        self, incognito_client, db_session
    ):
        # 1. Sign up via landing page
        incognito_client.post(
            "/api/email-signup", json={"email": "merge@example.com"}
        )
        lite = db_session.exec(
            select(Users).where(Users.user_email == "merge@example.com")
        ).first()
        assert lite is not None
        original_consent_ts = lite.email_marketing_consent_at
        original_user_id = lite.user_id

        # 2. Simulate Google OAuth callback for the same email with Google's `sub`
        google_sub = "google-oauth-sub-12345"
        oauth_user = SimpleNamespace(
            user_id=google_sub,
            user_email="merge@example.com",
        )
        existing_user, _ = user_exists(oauth_user, db_session)

        # 3. Assertions: row reconciled, consent preserved
        assert existing_user is not None
        assert existing_user.user_id == google_sub
        assert existing_user.user_id != original_user_id
        assert existing_user.email_marketing_consent is True
        assert existing_user.email_marketing_consent_at == original_consent_ts

        # 4. Single row, no duplicate
        all_rows = db_session.exec(
            select(Users).where(Users.user_email == "merge@example.com")
        ).all()
        assert len(all_rows) == 1
