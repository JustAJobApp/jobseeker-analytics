# backend/utils/redirect_utils.py
from fastapi.responses import RedirectResponse
from utils.config_utils import get_settings

settings = get_settings()

class Redirects:
    @staticmethod
    def to_frontend(path: str = "") -> RedirectResponse:
        """Base redirect to the frontend application."""
        return RedirectResponse(url=f"{settings.APP_URL}{path}", status_code=303)

    @staticmethod
    def to_dashboard() -> RedirectResponse:
        return Redirects.to_frontend("/dashboard")

    @staticmethod
    def to_error(reason: str) -> RedirectResponse:
        return Redirects.to_frontend(f"/errors?message={reason}")

    @staticmethod
    def to_onboarding() -> RedirectResponse:
        return Redirects.to_frontend("/onboarding")

    @staticmethod
    def to_email_sync_setup() -> RedirectResponse:
        return Redirects.to_frontend("/email-sync-setup")

    @staticmethod
    def to_signup() -> RedirectResponse:
        return Redirects.to_frontend("/login?signup=true")