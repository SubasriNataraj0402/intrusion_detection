from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Attack, Traffic, User
from app.security import get_current_user

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("")
def generate_report(
    days: int = Query(7, le=90),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    since = datetime.utcnow() - timedelta(days=days)

    total_flows = db.query(func.count(Traffic.flow_id)).filter(Traffic.created_at >= since).scalar()
    total_attacks = db.query(func.count(Attack.attack_id)).filter(Attack.time >= since).scalar()
    avg_confidence = db.query(func.avg(Attack.confidence)).filter(Attack.time >= since).scalar()

    by_type = (
        db.query(Attack.attack_name, func.count(Attack.attack_id))
        .filter(Attack.time >= since)
        .group_by(Attack.attack_name)
        .all()
    )
    by_severity = (
        db.query(Attack.severity, func.count(Attack.attack_id))
        .filter(Attack.time >= since)
        .group_by(Attack.severity)
        .all()
    )

    return {
        "period_days": days,
        "generated_at": datetime.utcnow(),
        "total_flows_analyzed": int(total_flows or 0),
        "total_attacks_detected": int(total_attacks or 0),
        "average_confidence": round(float(avg_confidence or 0), 4),
        "attacks_by_type": [{"attack_name": a, "count": c} for a, c in by_type],
        "attacks_by_severity": [{"severity": s.value if s else "unknown", "count": c} for s, c in by_severity],
    }
