import enum
import uuid
from datetime import datetime

from sqlalchemy import Column, String, Float, Integer, DateTime, Boolean, Enum, ForeignKey
from sqlalchemy.orm import relationship

from app.database import Base


def gen_uuid():
    return str(uuid.uuid4())


class Role(str, enum.Enum):
    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"


class Severity(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=gen_uuid)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False, index=True)
    hashed_password = Column(String, nullable=False)
    role = Column(Enum(Role), default=Role.viewer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class Traffic(Base):
    __tablename__ = "traffic"

    flow_id = Column(String, primary_key=True, default=gen_uuid)
    source_ip = Column(String, index=True)
    destination_ip = Column(String, index=True)
    source_port = Column(Integer)
    destination_port = Column(Integer)
    protocol = Column(String)
    duration = Column(Float)
    total_packets = Column(Integer)
    total_bytes = Column(Integer)
    avg_packet_size = Column(Float)
    syn_count = Column(Integer)
    ack_count = Column(Integer)
    fin_count = Column(Integer)
    packets_per_sec = Column(Float)
    bytes_per_sec = Column(Float)
    label = Column(String, default="normal")
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    attacks = relationship("Attack", back_populates="flow")


class Attack(Base):
    __tablename__ = "attacks"

    attack_id = Column(String, primary_key=True, default=gen_uuid)
    flow_id = Column(String, ForeignKey("traffic.flow_id"), nullable=True)
    source_ip = Column(String, index=True)
    destination_ip = Column(String, index=True)
    attack_name = Column(String, index=True)
    confidence = Column(Float)
    severity = Column(Enum(Severity))
    risk_score = Column(Integer)
    recommendation = Column(String)
    explanation = Column(String)  # JSON-encoded SHAP top features
    detector = Column(String, default="random_forest")
    time = Column(DateTime, default=datetime.utcnow, index=True)

    flow = relationship("Traffic", back_populates="attacks")


class Alert(Base):
    __tablename__ = "alerts"

    alert_id = Column(String, primary_key=True, default=gen_uuid)
    attack_id = Column(String, ForeignKey("attacks.attack_id"), nullable=True)
    message = Column(String)
    severity = Column(Enum(Severity))
    status = Column(String, default="open")
    acknowledged = Column(Boolean, default=False)
    created_time = Column(DateTime, default=datetime.utcnow, index=True)


class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id = Column(String, primary_key=True, default=gen_uuid)
    ip_address = Column(String, unique=True, index=True, nullable=False)
    reason = Column(String, nullable=False)
    attack_type = Column(String, default="manual")
    blocked_by = Column(String, default="auto")  # 'auto' or 'admin'
    status = Column(String, default="active")   # 'active' or 'unblocked'
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

