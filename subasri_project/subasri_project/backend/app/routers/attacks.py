from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Attack, User
from app.schemas import AttackOut
from app.security import get_current_user

router = APIRouter(prefix="/attacks", tags=["attacks"])


@router.get("", response_model=list[AttackOut])
def list_attacks(
    limit: int = Query(100, le=1000),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    rows = db.query(Attack).order_by(desc(Attack.time)).limit(limit).all()
    return rows
