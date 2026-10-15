import json
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Attack
from app.threat_intel.gemini import analyze_attack_with_gemini, chat_with_gemini

router = APIRouter(prefix="/api/ai", tags=["ai"])

class AttackAnalyzeRequest(BaseModel):
    attack_id: str | None = None
    attack_name: str | None = "unknown_anomaly"
    confidence: float | None = 0.8
    severity: str | None = "high"
    risk_score: int | None = 75
    source_ip: str | None = "0.0.0.0"
    destination_ip: str | None = "0.0.0.0"
    explanation: dict | list | str | None = None

class ChatRequest(BaseModel):
    message: str
    context: dict | None = None

@router.post("/analyze")
def analyze_attack(req: AttackAnalyzeRequest, db: Session = Depends(get_db)):
    attack_data = req.model_dump()
    
    if req.attack_id:
        attack = db.query(Attack).filter(Attack.attack_id == req.attack_id).first()
        if attack:
            explanation = {}
            if attack.explanation:
                try:
                    explanation = json.loads(attack.explanation)
                except Exception:
                    pass
            attack_data = {
                "attack_name": attack.attack_name,
                "confidence": attack.confidence,
                "severity": attack.severity.value if hasattr(attack.severity, 'value') else str(attack.severity),
                "risk_score": attack.risk_score,
                "source_ip": attack.source_ip,
                "destination_ip": attack.destination_ip,
                "detector": attack.detector,
                "explanation": explanation
            }
            
    report = analyze_attack_with_gemini(attack_data)
    return report

@router.post("/chat")
def chat_analyst(req: ChatRequest):
    reply = chat_with_gemini(req.message, req.context)
    return {"reply": reply}
