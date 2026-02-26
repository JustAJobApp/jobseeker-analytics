from contextlib import asynccontextmanager
from datetime import datetime
import logging
import re

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from utils.config_utils import get_settings
import database  # noqa: F401 - used for dependency injection
from scheduler.background_scheduler import start_scheduler, stop_scheduler
# Import routes
from routes import email_routes, auth_routes, file_routes, users_routes, start_date_routes, job_applications_routes, coach_routes, onboarding_routes, stripe_webhook_routes, payment_routes


class OAuthRedactionFilter(logging.Filter):
    """
    Intercepts Uvicorn access logs and redacts sensitive OAuth query parameters.
    """
    def filter(self, record):
        # Uvicorn access logs pass the request line components in record.args
        if hasattr(record, "args") and isinstance(record.args, tuple):
            new_args = []
            for arg in record.args:
                if isinstance(arg, str) and "/auth/google" in arg:
                    # Redact the 'code' and 'state' query parameters
                    arg = re.sub(r'(code|state)=[^&\s]+', r'\1=[REDACTED]', arg)
                new_args.append(arg)
            record.args = tuple(new_args)
            
        # Also check the main message string just in case
        if isinstance(record.msg, str) and "/auth/google" in record.msg:
            record.msg = re.sub(r'(code|state)=[^&\s]+', r'\1=[REDACTED]', record.msg)
            
        return True

# 2. Define the app logger and attach the redaction filter
logger = logging.getLogger(__name__)
logger.addFilter(OAuthRedactionFilter())

@asynccontextmanager
async def lifespan(app: FastAPI):
    # App startup
    settings = get_settings()

    if not settings.is_publicly_deployed:
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s - %(message)s")
        logger.setLevel(logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")
        logger.setLevel(logging.INFO)

    # Log the Security Integrity Fingerprint
    fingerprint = settings.get_security_fingerprint()
    logger.info("================================================")
    logger.info("SECURITY INTEGRITY AUDIT")
    logger.info(f"Configuration Fingerprint: {fingerprint}")
    logger.info("================================================")
    
    # Start background scheduler for Always Open email sync (production only)
    if settings.is_publicly_deployed:
        start_scheduler()
        logger.info("Background scheduler started for Always Open email sync")

    yield

    # App shutdown
    if settings.is_publicly_deployed:
        stop_scheduler()
        logger.info("Background scheduler stopped")

app = FastAPI(lifespan=lifespan)
settings = get_settings()
APP_URL = settings.APP_URL

# Configure session middleware with proper settings for production
if settings.is_publicly_deployed:
    app.add_middleware(
        SessionMiddleware, 
        secret_key=settings.COOKIE_SECRET,
        session_cookie="session",
        max_age=3600,
        same_site="lax",
        https_only=True,
        domain=settings.ORIGIN
    )
else:
    app.add_middleware(SessionMiddleware, secret_key=settings.COOKIE_SECRET)
app.mount("/static", StaticFiles(directory="static"), name="static")

# Register routes
app.include_router(auth_routes.router)
app.include_router(email_routes.router)
app.include_router(file_routes.router)
app.include_router(users_routes.router)
app.include_router(start_date_routes.router)
app.include_router(job_applications_routes.router)
app.include_router(coach_routes.router)
app.include_router(onboarding_routes.router)
app.include_router(stripe_webhook_routes.router)
app.include_router(payment_routes.router)

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter  # Ensure limiter is assigned

# Add SlowAPI middleware for rate limiting
app.add_middleware(SlowAPIMiddleware)

# Add CORS middleware
# Explicit subdomain list to prevent subdomain takeover attacks
ALLOWED_ORIGINS = [
    "https://justajobapp.com",
    "https://www.justajobapp.com",
    "https://app.justajobapp.com",
    "https://www.app.justajobapp.com",
    "https://api.justajobapp.com",
    "https://www.api.justajobapp.com",
]

if settings.is_publicly_deployed:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Step-Up-Auth"],
    )
else:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[settings.APP_URL, settings.API_URL],
        allow_credentials=True,
        allow_methods=["*"],  # Allow all HTTP methods (GET, POST, etc.)
        allow_headers=["*"],  # Allow all headers
        expose_headers=["X-Step-Up-Auth"],
    )


# Security headers middleware to prevent MIME-sniffing and clickjacking attacks
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, is_publicly_deployed: bool = False):
        super().__init__(app)
        self.is_publicly_deployed = is_publicly_deployed

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"

        # FIX CWE-525: Prevent caching of API responses
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        # HSTS: only set in production over HTTPS
        if self.is_publicly_deployed:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


app.add_middleware(SecurityHeadersMiddleware, is_publicly_deployed=settings.is_publicly_deployed)


# Rate limit exception handler
@app.exception_handler(RateLimitExceeded)
async def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
    raise HTTPException(
        status_code=429,
        detail="Too many requests. Please try again later.",
    )

@app.get("/")
async def root():
    return {"message": "success"}

@app.get("/robots.txt", response_class=PlainTextResponse)
def get_robots():
    return "User-agent: *\nDisallow: /"

@app.get("/heartbeat")
@limiter.limit("4/hour")
async def heartbeat(request: Request):
    """
    Lightweight endpoint to check if the backend is alive.
    No rate limiting applied to prevent blocking health checks.
    """
    return {"status": "alive", "timestamp": datetime.now().isoformat()}



# Run the app using Uvicorn
if __name__ == "__main__":
    import uvicorn
    import logging

    # 1. Start uvicorn without starting the server immediately to get the loggers
    config = uvicorn.Config(app, host="0.0.0.0", port=8000, log_level="info")
    server = uvicorn.Server(config)
    
    # 2. Attach the redaction filter to Uvicorn's access logger
    access_logger = logging.getLogger("uvicorn.access")
    access_logger.addFilter(OAuthRedactionFilter())
    
    # 3. Run the server
    server.run()