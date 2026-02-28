import json
import hashlib
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict, NoDecode
from typing import List
from typing_extensions import Annotated
import logging

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    GOOGLE_CLIENT_ID: str = "default-for-local"
    GOOGLE_CLIENT_SECRET: str = "default-for-local"
    GOOGLE_CLIENT_REDIRECT_URI: str = "http://localhost:8000/auth/google"
    GOOGLE_API_KEY: str
    IPINFO_TOKEN: str = "default-for-local"
    COOKIE_SECRET: str
    TOKEN_ENCRYPTION_KEY: str = "default-for-local"  # Fernet key for encrypting OAuth tokens in DB
    STRIPE_SECRET_KEY: str = "sk_test_placeholder_for_dev"
    STRIPE_WEBHOOK_SECRET: str = "whsec_placeholder_for_dev"
    ENV: str = "dev"
    APP_URL: str = "http://localhost:3000"  # Frontend URL - default for local dev
    API_URL: str = "http://localhost:8000"  # Backend API URL - default for local dev
    GOOGLE_SCOPES: Annotated[List[str], NoDecode] = '["https://www.googleapis.com/auth/gmail.readonly", "openid", "https://www.googleapis.com/auth/userinfo.email"]'
    # Basic scopes for signup (no email read access)
    GOOGLE_SCOPES_BASIC: Annotated[List[str], NoDecode] = '["openid", "https://www.googleapis.com/auth/userinfo.email"]'
    ORIGIN: str = "localhost"  # Default for local dev
    DATABASE_URL: str = "default-for-local"
    DATABASE_URL_LOCAL_VIRTUAL_ENV: str = (
        "postgresql://postgres:postgres@localhost:5433/jobseeker_analytics"
    )
    DATABASE_URL_DOCKER: str = (
        "postgresql://postgres:postgres@db:5432/jobseeker_analytics"
    )
    BATCH_SIZE: int = 10000
    DEV_USER_GMAIL: str = "insert-your-email-here@gmail.com"
    DEV_USER_IS_ACTIVE: bool = True
    AWS_KMS_ACCESS_KEY_ID: str = "default-for-local"
    AWS_KMS_SECRET_ACCESS_KEY: str = "default-for-local"
    AWS_KMS_KEY_ARN: str = "default-for-local"
    AWS_DATABASE_REGION: str = "default-for-local"

    @field_validator("GOOGLE_SCOPES", "GOOGLE_SCOPES_BASIC", mode="before")
    @classmethod
    def decode_scopes(cls, v: str) -> List[str]:
        logger.info("Decoded scopes from string: %s", json.loads(v.strip("'\"")))
        return json.loads(v.strip("'\""))

    @property
    def is_publicly_deployed(self) -> bool:
        return self.ENV in ["prod", "staging"]

    @property
    def batch_size_by_env(self) -> int:
        return (
            self.BATCH_SIZE if self.is_publicly_deployed else 200
        )  # corresponds to Gemini API rate limit per day (200)

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="allow"
    )

    def get_security_fingerprint(self) -> str:
        """
        Generates a non-reversible SHA-256 hash of security-critical configuration.
        Selected keys based on the JustAJobApp security profile.
        """
        critical_keys = [
            "ENV",                        # Environment boundary
            "NODE_ENV",                   # Environment boundary
            "GOOGLE_API_KEY",             # LLM function
            "GOOGLE_CLIENT_ID",           # OAuth Flow
            "GOOGLE_CLIENT_SECRET",       # OAuth Flow
            "GOOGLE_CLIENT_REDIRECT_URI", # OAuth Flow
            "COOKIE_SECRET",              # Session Integrity
            "TOKEN_ENCRYPTION_KEY",       # DB Credential Security
            "DATABASE_URL",               # DB Credential Security
            "APP_URL",                    # Trusted Frontend Origin
            "API_URL",                    # Trusted Backend Origin
            "NEXT_PUBLIC_APP_URL",        # Trusted Frontend Origin
            "NEXT_PUBLIC_API_URL",        # Trusted Backend Origin
            "ORIGIN",                     # Cookie Domain
            "STRIPE_WEBHOOK_SECRET",      # Payments Security
            "STRIPE_SECRET_KEY",          # Payments Security
            "IPINFO_TOKEN",               # Geographic boundary
            "GH_PRIVATE_KEY",             # GitHub App Config (Maintainer Tooling)
            "GH_APP_ID",                  # GitHub App Config (Maintainer Tooling)
            "GH_INSTALLATION_ID",         # GitHub App Config (Maintainer Tooling)
            "AWS_DATABASE_NAME",          # AWS Config
            "AWS_DATABASE_REGION",        # AWS Config
            "AWS_KMS_ACCESS_KEY_ID",      # AWS Config
            "AWS_KMS_SECRET_ACCESS_KEY",  # AWS Config
            "AWS_KMS_KEY_ARN"                 # AWS Config
        ]
        
        # Build a sorted dictionary to ensure the hash is consistent every time
        config_data = {
            key: str(getattr(self, key, "") or "").strip() 
            for key in sorted(critical_keys)
        }
        config_json = json.dumps(config_data, sort_keys=True)
        
        return hashlib.sha256(config_json.encode()).hexdigest()

class ConfigSettings(Settings):
    @property
    def google_oauth2_config(self):
        obj = {
            "web": {
                "client_id": self.GOOGLE_CLIENT_ID,
                "client_secret": self.GOOGLE_CLIENT_SECRET,
                "redirect_uris": [self.GOOGLE_CLIENT_REDIRECT_URI],
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        }
        return obj

settings = ConfigSettings(_env_file=".env", _env_file_encoding="utf-8")
