THREAT_CATALOG = {
    "normal": {
        "display_name": "Normal Traffic",
        "base_severity": "low",
        "recommendation": "No action required.",
    },
    "port_scan": {
        "display_name": "Port Scan",
        "base_severity": "medium",
        "recommendation": "Block source IP at the firewall; review exposed services on scanned ports.",
    },
    "ddos": {
        "display_name": "DDoS",
        "base_severity": "critical",
        "recommendation": "Block source IP(s); enable rate limiting / upstream scrubbing; alert on-call.",
    },
    "brute_force": {
        "display_name": "Brute Force",
        "base_severity": "high",
        "recommendation": "Lock affected account; enforce MFA; block source IP after repeated failures.",
    },
    "unknown_anomaly": {
        "display_name": "Unknown Anomaly",
        "base_severity": "high",
        "recommendation": "Traffic deviates from known-normal baseline. Escalate to an analyst for manual review.",
    },
}

_SEVERITY_RISK = {"low": 20, "medium": 50, "high": 75, "critical": 95}
_SEVERITY_ORDER = ["low", "medium", "high", "critical"]


def _bump_severity(base: str, confidence: float) -> str:
    idx = _SEVERITY_ORDER.index(base)
    if confidence > 0.95 and idx < len(_SEVERITY_ORDER) - 1:
        idx += 1
    return _SEVERITY_ORDER[idx]


def assess(attack_name: str, confidence: float) -> dict:
    entry = THREAT_CATALOG.get(attack_name, THREAT_CATALOG["unknown_anomaly"])
    severity = _bump_severity(entry["base_severity"], confidence)
    risk_score = min(100, int(_SEVERITY_RISK[severity] * confidence + (1 - confidence) * 10))
    return {
        "threat_name": entry["display_name"],
        "severity": severity,
        "risk_score": risk_score,
        "recommendation": entry["recommendation"],
    }
