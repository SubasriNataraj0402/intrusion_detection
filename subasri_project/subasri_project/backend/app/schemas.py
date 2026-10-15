from datetime import datetime
from typing import Optional, List

from pydantic import BaseModel, EmailStr


class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: str = "viewer"


class UserOut(BaseModel):
    id: str
    name: str
    email: str
    role: str

    class Config:
        from_attributes = True


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


class TrafficOut(BaseModel):
    flow_id: str
    source_ip: str
    destination_ip: str
    source_port: Optional[int]
    destination_port: Optional[int]
    protocol: str
    duration: float
    total_packets: int
    total_bytes: int
    avg_packet_size: float
    syn_count: int
    ack_count: int
    fin_count: int
    packets_per_sec: float
    bytes_per_sec: float
    label: str
    created_at: datetime

    class Config:
        from_attributes = True


class AttackOut(BaseModel):
    attack_id: str
    source_ip: str
    destination_ip: str
    attack_name: str
    confidence: float
    severity: str
    risk_score: int
    recommendation: str
    explanation: Optional[str]
    detector: str
    time: datetime

    class Config:
        from_attributes = True


class AlertOut(BaseModel):
    alert_id: str
    attack_id: Optional[str]
    message: str
    severity: str
    status: str
    acknowledged: bool
    created_time: datetime

    class Config:
        from_attributes = True


class PredictRequest(BaseModel):
    duration: float
    total_packets: int
    total_bytes: int
    avg_packet_size: float
    syn_count: int
    ack_count: int
    fin_count: int
    packets_per_sec: float
    bytes_per_sec: float
    source_ip: str = "0.0.0.0"
    destination_ip: str = "0.0.0.0"
    source_port: int = 0
    destination_port: int = 0
    protocol: str = "TCP"


class PredictResponse(BaseModel):
    attack_name: str
    confidence: float
    severity: str
    risk_score: int
    recommendation: str
    is_anomaly: bool
    anomaly_score: float
    explanation: List[dict]


class DashboardSummary(BaseModel):
    total_packets: int
    active_connections: int
    current_threats: int
    detection_rate: float
    packets_per_sec_series: List[dict]
    protocol_distribution: List[dict]
    top_attack_types: List[dict]
    severity_distribution: List[dict]
    top_attacking_ips: List[dict]
    hourly_attacks: List[dict]


class BlockedIPOut(BaseModel):
    id: str
    ip_address: str
    reason: str
    attack_type: str
    blocked_by: str
    status: str
    created_at: datetime

    class Config:
        from_attributes = True


class BlockIPRequest(BaseModel):
    ip_address: str
    reason: Optional[str] = "Manual administrative block"
    attack_type: Optional[str] = "manual"

