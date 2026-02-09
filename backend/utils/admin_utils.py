import logging
from fastapi import HTTPException, Depends, Request
from sqlmodel import select, and_
from database import DBSession
from utils.onboarding_utils import require_onboarding_complete
from db.users import CoachClientLink

logger = logging.getLogger(__name__)

def get_context_user_id(
    request: Request,
    db_session: DBSession,
    authenticated_user_id: str = Depends(require_onboarding_complete)
) -> str:
    """
    Determines the target user_id for the query.
    If 'X-View-As' header is present, verifies coach-client relationship.
    Otherwise returns the authenticated user.
    """
    # Check if the caller wants to view a specific client's data (header only for security)
    target_client_id = request.headers.get("X-View-As")
    logger.info(
        "get_context_user_id: authenticated_user_id=%s, target_client_id=%s, path=%s", 
        authenticated_user_id, target_client_id, request.url.path
    )

    if not target_client_id:
        return authenticated_user_id

    # If attempting to view someone else, verify the relationship
    if target_client_id != authenticated_user_id:
        statement = select(CoachClientLink).where(
            and_(
                CoachClientLink.coach_id == authenticated_user_id,
                CoachClientLink.client_id == target_client_id,
                CoachClientLink.end_date == None # noqa: E711
            )
        )
        relationship = db_session.exec(statement).first()

        logger.info(
            "get_context_user_id: relationship check result=%s for coach_id=%s client_id=%s", 
            bool(relationship), authenticated_user_id, target_client_id
        )

        if not relationship:
            logger.warning(
                "get_context_user_id: unauthorized coach access attempt coach_id=%s client_id=%s", 
                authenticated_user_id, target_client_id
            )
            raise HTTPException(
                status_code=403, 
                detail="Access denied: You are not an authorized coach."
            )
            
    return target_client_id