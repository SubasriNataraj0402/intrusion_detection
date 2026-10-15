"""Shared detection pipeline: flow features -> ML prediction -> threat intel ->
persistence -> alerting -> websocket broadcast. Used by the live capture callback,
the /api/predict endpoint, and the /api/upload-pcap endpoint so all three paths
produce identical Traffic/Attack/Alert records.
"""
import asyncio
import json
import logging

from app.alerts.engine import maybe_raise_alert
from app.blocking.engine import blocking_engine
from app.database import SessionLocal
from app.ml import predictor
from app.models import Traffic, Attack, Severity
from app.threat_intel.engine import assess
from app.websocket.manager import manager

logger = logging.getLogger("nids.pipeline")

_main_loop: asyncio.AbstractEventLoop | None = None


def set_main_loop(loop: asyncio.AbstractEventLoop):
    global _main_loop
    _main_loop = loop


def _broadcast(event: str, payload: dict):
    if _main_loop is None:
        return
    try:
        asyncio.run_coroutine_threadsafe(manager.broadcast(event, payload), _main_loop)
    except RuntimeError:
        pass


def process_flow(features: dict, persist_traffic: bool = True) -> dict:
    if not predictor.models_available():
        logger.warning("ML models not trained yet; run `python -m app.ml.train` first.")
        return {"error": "models_not_trained"}

    src_ip = features.get("source_ip", "0.0.0.0")
    if blocking_engine.is_blocked(src_ip):
        logger.info(f"🚫 Dropped flow from active blocked IP: {src_ip}")
        return {
            "attack_name": "blocked_traffic",
            "confidence": 1.0,
            "severity": "high",
            "risk_score": 100,
            "recommendation": f"Traffic automatically dropped. IP {src_ip} is blocked.",
            "is_anomaly": True,
            "anomaly_score": 1.0,
            "explanation": [],
            "status": "blocked"
        }

    result = predictor.predict(features)
    intel = assess(result["attack_name"], result["confidence"])

    db = SessionLocal()
    try:
        traffic_row = None
        if persist_traffic:
            traffic_row = Traffic(
                source_ip=src_ip,
                destination_ip=features.get("destination_ip", "0.0.0.0"),
                source_port=features.get("source_port", 0),
                destination_port=features.get("destination_port", 0),
                protocol=features.get("protocol", "TCP"),
                duration=features["duration"],
                total_packets=features["total_packets"],
                total_bytes=features["total_bytes"],
                avg_packet_size=features["avg_packet_size"],
                syn_count=features["syn_count"],
                ack_count=features["ack_count"],
                fin_count=features["fin_count"],
                packets_per_sec=features["packets_per_sec"],
                bytes_per_sec=features["bytes_per_sec"],
                label=result["attack_name"],
            )
            db.add(traffic_row)
            db.commit()
            db.refresh(traffic_row)
            _broadcast("traffic", {
                "flow_id": traffic_row.flow_id,
                "source_ip": traffic_row.source_ip,
                "destination_ip": traffic_row.destination_ip,
                "protocol": traffic_row.protocol,
                "total_packets": traffic_row.total_packets,
                "total_bytes": traffic_row.total_bytes,
                "label": traffic_row.label,
                "created_at": traffic_row.created_at,
            })

        attack_row = None
        if result["attack_name"] != "normal":
            attack_row = Attack(
                flow_id=traffic_row.flow_id if traffic_row else None,
                source_ip=src_ip,
                destination_ip=features.get("destination_ip", "0.0.0.0"),
                attack_name=result["attack_name"],
                confidence=result["confidence"],
                severity=Severity(intel["severity"]),
                risk_score=intel["risk_score"],
                recommendation=intel["recommendation"],
                explanation=json.dumps(result["explanation"]),
                detector="random_forest" if not result["is_anomaly"] else "isolation_forest",
            )
            db.add(attack_row)
            db.commit()
            db.refresh(attack_row)
            _broadcast("attack", {
                "attack_id": attack_row.attack_id,
                "source_ip": attack_row.source_ip,
                "destination_ip": attack_row.destination_ip,
                "attack_name": attack_row.attack_name,
                "confidence": attack_row.confidence,
                "severity": attack_row.severity.value,
                "risk_score": attack_row.risk_score,
                "recommendation": attack_row.recommendation,
                "time": attack_row.time,
            })

            alert = maybe_raise_alert(db, attack_row)
            if alert:
                _broadcast("alert", {
                    "alert_id": alert.alert_id,
                    "message": alert.message,
                    "severity": alert.severity.value,
                    "created_time": alert.created_time,
                })

            # Auto-block IP if attack severity is medium, high, or critical with confidence >= 0.5
            if intel["severity"] in ("medium", "high", "critical") and result["confidence"] >= 0.5:
                blocked_record = blocking_engine.block_ip(
                    ip_address=src_ip,
                    reason=f"Auto-blocked due to {intel['severity']} severity {result['attack_name']} attack ({int(result['confidence']*100)}% conf)",
                    attack_type=result["attack_name"],
                    blocked_by="auto"
                )
                if blocked_record:
                    _broadcast("ip_blocked", blocked_record)


        return {
            "attack_name": result["attack_name"],
            "confidence": result["confidence"],
            "severity": intel["severity"],
            "risk_score": intel["risk_score"],
            "recommendation": intel["recommendation"],
            "is_anomaly": result["is_anomaly"],
            "anomaly_score": result["anomaly_score"],
            "explanation": result["explanation"],
        }
    finally:
        db.close()

