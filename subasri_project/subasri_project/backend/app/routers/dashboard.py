from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Traffic, Attack, User
from app.schemas import DashboardSummary
from app.security import get_current_user

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("", response_model=DashboardSummary)
def dashboard(db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    now = datetime.utcnow()
    since_1h = now - timedelta(hours=1)
    since_24h = now - timedelta(hours=24)

    total_packets = db.query(func.coalesce(func.sum(Traffic.total_packets), 0)).scalar()
    active_connections = db.query(func.count(Traffic.flow_id)).filter(Traffic.created_at >= since_1h).scalar()
    current_threats = db.query(func.count(Attack.attack_id)).filter(Attack.time >= since_1h).scalar()

    total_flows = db.query(func.count(Traffic.flow_id)).scalar() or 1
    total_attacks = db.query(func.count(Attack.attack_id)).scalar() or 0
    detection_rate = round((total_attacks / total_flows) * 100, 2)

    if db.bind.dialect.name == "sqlite":
        minute_col = func.strftime("%Y-%m-%dT%H:%M:00", Traffic.created_at).label("minute")
    else:
        minute_col = func.date_trunc("minute", Traffic.created_at).label("minute")

    pps_rows = (
        db.query(
            minute_col,
            func.sum(Traffic.total_packets).label("packets"),
        )
        .filter(Traffic.created_at >= since_1h)
        .group_by("minute")
        .order_by("minute")
        .all()
    )
    packets_per_sec_series = [{"time": str(r.minute), "packets": int(r.packets or 0)} for r in pps_rows]

    proto_rows = (
        db.query(Traffic.protocol, func.count(Traffic.flow_id))
        .group_by(Traffic.protocol)
        .all()
    )
    protocol_distribution = [{"protocol": p or "unknown", "count": c} for p, c in proto_rows]

    attack_type_rows = (
        db.query(Attack.attack_name, func.count(Attack.attack_id))
        .group_by(Attack.attack_name)
        .order_by(func.count(Attack.attack_id).desc())
        .limit(10)
        .all()
    )
    top_attack_types = [{"attack_name": a, "count": c} for a, c in attack_type_rows]

    severity_rows = (
        db.query(Attack.severity, func.count(Attack.attack_id))
        .group_by(Attack.severity)
        .all()
    )
    severity_distribution = [{"severity": s.value if s else "unknown", "count": c} for s, c in severity_rows]

    ip_rows = (
        db.query(Attack.source_ip, func.count(Attack.attack_id))
        .group_by(Attack.source_ip)
        .order_by(func.count(Attack.attack_id).desc())
        .limit(10)
        .all()
    )
    top_attacking_ips = [{"source_ip": ip, "count": c} for ip, c in ip_rows]

    if db.bind.dialect.name == "sqlite":
        hour_col = func.strftime("%Y-%m-%dT%H:00:00", Attack.time).label("hour")
    else:
        hour_col = func.date_trunc("hour", Attack.time).label("hour")

    hourly_rows = (
        db.query(
            hour_col,
            func.count(Attack.attack_id).label("count"),
        )
        .filter(Attack.time >= since_24h)
        .group_by("hour")
        .order_by("hour")
        .all()
    )
    hourly_attacks = [{"hour": str(r.hour), "count": r.count} for r in hourly_rows]

    return DashboardSummary(
        total_packets=int(total_packets or 0),
        active_connections=int(active_connections or 0),
        current_threats=int(current_threats or 0),
        detection_rate=detection_rate,
        packets_per_sec_series=packets_per_sec_series,
        protocol_distribution=protocol_distribution,
        top_attack_types=top_attack_types,
        severity_distribution=severity_distribution,
        top_attacking_ips=top_attacking_ips,
        hourly_attacks=hourly_attacks,
    )
