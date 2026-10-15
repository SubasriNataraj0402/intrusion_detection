import logging

from sqlalchemy.orm import Session

from app.config import settings
from app.models import Alert, Attack

logger = logging.getLogger("nids.alerts")


def maybe_raise_alert(db: Session, attack: Attack) -> Alert | None:
    """Persist an alert when a prediction crosses the confidence threshold.

    Extend this with real Email/Telegram/Slack senders under app/alerts/ as needed;
    the browser gets alerts in real time already via the websocket broadcast in
    the router that calls this function.
    """
    if attack.confidence < settings.alert_confidence_threshold or attack.attack_name == "normal":
        return None

    alert = Alert(
        attack_id=attack.attack_id,
        message=f"{attack.attack_name} detected from {attack.source_ip} "
                f"({attack.confidence * 100:.1f}% confidence, severity={attack.severity.value})",
        severity=attack.severity,
        status="open",
        acknowledged=False,
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    logger.warning(alert.message)
    return alert
