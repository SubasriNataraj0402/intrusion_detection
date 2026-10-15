from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Alert, User
from app.schemas import AlertOut
from app.security import get_current_user

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=list[AlertOut])
def list_alerts(
    limit: int = Query(100, le=1000),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    rows = db.query(Alert).order_by(desc(Alert.created_time)).limit(limit).all()
    return rows


@router.post("/{alert_id}/acknowledge", response_model=AlertOut)
def acknowledge_alert(alert_id: str, db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    alert = db.query(Alert).filter(Alert.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.acknowledged = True
    alert.status = "acknowledged"
    db.commit()
    db.refresh(alert)
    return alert
