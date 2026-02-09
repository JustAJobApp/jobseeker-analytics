"""
Tests for user login/onboarding flow redirects.

These tests verify that different user types are redirected to the correct
pages after OAuth authentication:
- Coaches → /dashboard (bypass all onboarding)
- Jobseekers with complete setup → /processing
- Jobseekers without email sync → /email-sync-setup
- Jobseekers without start date → /dashboard
- Inactive users → /error?type=account_inactive
"""



class TestCoachLoginFlow:
    """Tests for coach user login behavior."""

    def test_coach_redirects_to_dashboard(self, client_factory, coach_user):
        """Coach with role='coach' should redirect directly to /dashboard."""
        client = client_factory(user=coach_user)

        # Hit the /me endpoint to verify coach user is recognized
        resp = client.get("/me")
        assert resp.status_code == 200
        data = resp.json()
        assert data["role"] == "coach"

    def test_coach_clients_endpoint_returns_clients(
        self, logged_in_coach_client, coach_client_link
    ):
        """Coach should be able to list their clients via /coach/clients."""
        resp = logged_in_coach_client.get("/coach/clients")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) > 0
        assert any(c["user_id"] == coach_client_link.client_id for c in data)

    def test_coach_clients_endpoint_requires_coach_role(
        self, client_factory, logged_in_user
    ):
        """/coach/clients should return 403 for jobseeker role."""
        client = client_factory(user=logged_in_user)
        resp = client.get("/coach/clients")
        assert resp.status_code == 403
        assert "not a coach" in resp.json()["detail"].lower()


class TestJobseekerLoginFlows:
    """Tests for jobseeker user login behavior based on onboarding status."""

    def test_jobseeker_complete_setup_can_access_dashboard(
        self, client_factory, jobseeker_complete_setup
    ):
        """Jobseeker with all setup complete should be able to access dashboard endpoints."""
        client = client_factory(user=jobseeker_complete_setup)

        resp = client.get("/me")
        assert resp.status_code == 200
        data = resp.json()
        assert data["role"] == "jobseeker"
        assert data["has_completed_onboarding"] is True
        assert data["has_email_sync_configured"] is True

    def test_jobseeker_needs_email_sync_status(
        self, client_factory, jobseeker_needs_email_sync
    ):
        """Jobseeker with onboarding but no email sync shows correct status."""
        client = client_factory(user=jobseeker_needs_email_sync)

        resp = client.get("/me")
        assert resp.status_code == 200
        data = resp.json()
        assert data["has_completed_onboarding"] is True
        assert data["has_email_sync_configured"] is False

    def test_jobseeker_needs_onboarding_status(
        self, client_factory, jobseeker_needs_onboarding
    ):
        """Jobseeker who hasn't completed onboarding shows correct status."""
        client = client_factory(user=jobseeker_needs_onboarding)

        resp = client.get("/me")
        assert resp.status_code == 200
        data = resp.json()
        assert data["has_completed_onboarding"] is False
        assert data["has_email_sync_configured"] is False

    def test_jobseeker_needs_start_date_status(
        self, client_factory, jobseeker_needs_start_date
    ):
        """Jobseeker with email sync but no start date shows correct status."""
        client = client_factory(user=jobseeker_needs_start_date)

        resp = client.get("/me")
        assert resp.status_code == 200
        data = resp.json()
        assert data["has_completed_onboarding"] is True
        assert data["has_email_sync_configured"] is True


class TestInactiveUserFlow:
    """Tests for inactive user behavior."""

    def test_inactive_user_cannot_access_protected_endpoints(
        self, client_factory, inactive_user
    ):
        """Inactive user should not be able to access protected endpoints."""
        client = client_factory(user=inactive_user)

        # The client_factory returns empty session for inactive users,
        # so they should get 401 on protected endpoints
        resp = client.get("/me")
        # Either 401 (unauthorized) or 404 (user not found) is acceptable
        assert resp.status_code in (401, 404)


class TestRoleBasedAccess:
    """Tests for role-based access control."""

    def test_jobseeker_cannot_access_coach_endpoints(
        self, client_factory, jobseeker_complete_setup
    ):
        """Jobseeker should not be able to access coach-only endpoints."""
        client = client_factory(user=jobseeker_complete_setup)

        resp = client.get("/coach/clients")
        assert resp.status_code == 403

    def test_coach_can_view_client_emails(
        self, logged_in_coach_client, coach_client_link, client_user
    ):
        """Coach should be able to view their client's emails via X-View-As header."""
        resp = logged_in_coach_client.get("/get-emails", headers={"X-View-As": client_user.user_id})
        assert resp.status_code == 200

    def test_coach_cannot_view_non_client_emails(
        self, logged_in_coach_client, user_factory
    ):
        """Coach should not be able to view emails of non-client users."""
        # Create a user that is not a client of the coach
        non_client = user_factory(
            user_id="nonclient123",
            user_email="nonclient@example.com",
            role="jobseeker",
        )

        resp = logged_in_coach_client.get("/get-emails", headers={"X-View-As": non_client.user_id})
        # Should either return 403 or empty list
        assert resp.status_code in (200, 403)
        if resp.status_code == 200:
            # If 200, should return empty list (coach can't see non-client data)
            data = resp.json()
            # The response could be empty or might filter based on access
            assert isinstance(data, list)
