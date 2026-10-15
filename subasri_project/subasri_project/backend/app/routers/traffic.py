from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Traffic, User
from app.schemas import TrafficOut
from app.security import get_current_user

router = APIRouter(prefix="/traffic", tags=["traffic"])


@router.get("", response_model=list[TrafficOut])
def list_traffic(
    limit: int = Query(100, le=1000),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    rows = db.query(Traffic).order_by(desc(Traffic.created_at)).limit(limit).all()
    return rows
