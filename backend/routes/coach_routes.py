import logging
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlmodel import select
import database
from session.session_layer import validate_session
from db.users import Users, CoachClientLink
from utils.billing_utils import is_premium_eligible
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
logger = logging.getLogger(__name__)
router = APIRouter()

class CoachClientResponse:
    def __init__(self, user_id: str, user_email: str, start_date, role: str):
        self.user_id = user_id
        self.user_email = user_email
        self.start_date = start_date
        self.role = role

@router.get("/coach/clients")
@limiter.limit("10/minute")
async def list_coach_clients(request: Request, db_session: database.DBSession, user_id: str = Depends(validate_session)) -> List[dict]:
    """Return active clients for authenticated coach."""
    # Verify caller is a coach AND has premium access
    coach = db_session.exec(select(Users).where(Users.user_id == user_id)).first()
    if not coach:
        raise HTTPException(status_code=401, detail="User not found")
    if coach.role != "coach":
        raise HTTPException(status_code=403, detail="Access denied: not a coach")
    if not is_premium_eligible(db_session, coach):
        raise HTTPException(status_code=403, detail="Access denied: coach access requires premium plan")

    # NOTE: Use explicit == None comparison so SQLAlchemy generates IS NULL; avoid Python `is None` in the WHERE clause.
    statement = select(CoachClientLink).where(
        CoachClientLink.coach_id == user_id,
        CoachClientLink.end_date == None  # noqa: E711
    )
    links = db_session.exec(statement).all()
    logger.debug("/coach/clients coach_id=%s found_links=%s", user_id, [f"{link.coach_id}:{link.client_id}" for link in links])
    client_ids = [link.client_id for link in links]
    if not client_ids:
        return []

    clients_stmt = select(Users).where(Users.user_id.in_(client_ids))
    clients = db_session.exec(clients_stmt).all()
    logger.debug("/coach/clients resolved_clients=%s", [c.user_id for c in clients])
    return [
        {
            "user_id": c.user_id,
            "user_email": c.user_email,
            "start_date": c.start_date.isoformat() if c.start_date else None,
            "role": c.role,
        }
        for c in clients
    ]