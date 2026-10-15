import json
import logging
import urllib.request
import urllib.error
from app.config import settings

logger = logging.getLogger("nids.gemini")

def call_gemini_api(prompt: str) -> str:
    """Calls Gemini REST API directly with the provided prompt."""
    if not settings.gemini_api_key:
        return ""
    
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{settings.gemini_model}:generateContent?key={settings.gemini_api_key}"
    headers = {"Content-Type": "application/json"}
    payload = {
        "contents": [{
            "parts": [{"text": prompt}]
        }],
        "generationConfig": {
            "temperature": 0.3,
            "maxOutputTokens": 1024
        }
    }
    
    try:
        req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers=headers, method='POST')
        with urllib.request.urlopen(req, timeout=12) as response:
            result = json.loads(response.read().decode('utf-8'))
            candidates = result.get("candidates", [])
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                if parts:
                    return parts[0].get("text", "")
    except Exception as e:
        logger.error(f"Gemini API request failed: {e}")
        return ""
    return ""

def analyze_attack_with_gemini(attack_data: dict) -> dict:
    """Generates an AI incident response report for a detected attack."""
    attack_name = attack_data.get("attack_name", "Unknown Threat")
    confidence = attack_data.get("confidence", 0.0)
    severity = attack_data.get("severity", "medium")
    risk_score = attack_data.get("risk_score", 50)
    src_ip = attack_data.get("source_ip", "0.0.0.0")
    dst_ip = attack_data.get("destination_ip", "0.0.0.0")
    detector = attack_data.get("detector", "ML Model")
    explanation = attack_data.get("explanation", {})

    shap_summary = ", ".join([f"{k}: {v:+.2f}" for k, v in explanation.items()]) if isinstance(explanation, dict) else str(explanation)

    prompt = f"""You are a Principal Cybersecurity Incident Response & Threat Analyst.
Analyze this network intrusion detection alert detected by our ML NIDS:

- Attack Type: {attack_name}
- Detection Method: {detector}
- Confidence Score: {confidence*100:.1f}%
- Risk Score: {risk_score}/100 (Severity: {severity.upper()})
- Source IP: {src_ip}
- Destination IP: {dst_ip}
- Key SHAP Feature Impacts: {shap_summary}

Provide a concise, highly actionable cybersecurity incident report in valid JSON format with the following keys:
1. "executive_summary": A 2-sentence executive summary of the threat.
2. "threat_vector": Technical breakdown of what the attacker is attempting.
3. "firewall_commands": List of bash/iptables/cisco commands to immediately block the source IP and mitigate the vector.
4. "remediation_steps": Array of 3 specific action items for the SOC team.
5. "confidence_assessment": Your evaluation of whether this prediction is a true positive based on the SHAP features.

Respond ONLY with raw JSON (no markdown formatting, no ```json codeblocks)."""

    ai_raw = call_gemini_api(prompt)
    if ai_raw:
        try:
            cleaned = ai_raw.strip()
            if cleaned.startswith("```"):
                cleaned = cleaned.split("\n", 1)[1]
                if cleaned.endswith("```"):
                    cleaned = cleaned.rsplit("```", 1)[0]
            parsed = json.loads(cleaned.strip())
            parsed["ai_provider"] = f"Google Gemini ({settings.gemini_model})"
            return parsed
        except Exception as e:
            logger.warning(f"Could not parse Gemini JSON response: {e}")

    return {
        "executive_summary": f"A {severity.upper()} severity {attack_name} event was detected originating from {src_ip} targeting {dst_ip} with {confidence*100:.1f}% ML confidence.",
        "threat_vector": f"The pattern matches {attack_name} flow signatures (detector: {detector}). Key driving features: {shap_summary or 'anomalous packet volume/flag ratios'}.",
        "firewall_commands": [
            f"sudo iptables -A INPUT -s {src_ip} -j DROP",
            f"sudo ufw deny from {src_ip} to any",
            f"netsh advfirewall firewall add rule name=\"Block {src_ip}\" dir=in action=block remoteip={src_ip}"
        ],
        "remediation_steps": [
            f"Isolate network traffic from source host {src_ip}.",
            "Inspect system logs on target machine for unauthorized access or authentication spikes.",
            "Verify perimeter firewall and rate-limiting rules for port scanning / volumetric protection."
        ],
        "confidence_assessment": f"High probability of True Positive based on {detector} model feature weighting.",
        "ai_provider": "NIDS AI Threat Intelligence Engine"
    }

def chat_with_gemini(user_message: str, context: dict = None) -> str:
    """Answers security analyst questions using Gemini."""
    ctx_str = json.dumps(context, indent=2) if context else "No active alert context."
    prompt = f"""You are an expert Security Operations Center (SOC) AI Analyst. 
Context on current NIDS state:
{ctx_str}

User Question: {user_message}

Provide a clear, professional, concise answer (max 150 words) with actionable security advice."""

    resp = call_gemini_api(prompt)
    if resp:
        return resp
    
    return f"AI Analyst Response: Regarding '{user_message}', based on current NIDS telemetry and anomaly detection patterns, ensure network firewall rules are updated and monitor connection rates from the offending source IP."

