"""Mock backends used until core modules are integrated."""
import re
from datetime import datetime

def mock_analyze_email(text: str) -> dict:
    words = ["urgent", "verify", "password", "suspended", "account", "login"]
    found = [w for w in words if w in text.lower()]
    status = "Phishing" if len(found) >= 2 else ("Suspicious" if found else "Legitimate")
    return {"status": status, "confidence": 0.92, "suspicious_words": found}

def mock_analyze_url(url: str) -> dict:
    reasons = []
    if "bit.ly" in url or "tinyurl" in url: reasons.append("Shortened Link Detected")
    if "verify" in url or "login" in url: reasons.append("Credential Phishing Terminology")
    status = "Phishing" if len(reasons) >= 2 else ("Suspicious" if reasons else "Legitimate")
    return {"status": status, "confidence": 0.88, "reasons": reasons}

def mock_get_combined_assessment(e_res, u_res) -> dict:
    score = 85 if (e_res or {}).get("status") == "Phishing" or (u_res or {}).get("status") == "Phishing" else 20
    level = "High Risk" if score >= 70 else "Low Risk"
    return {"overall_risk_score": score, "risk_level": level, "recommendation": "Block communication and reset access credentials immediately."}

def mock_get_history() -> list:
    return [
        {"id": 1, "date": "2026-11-02 14:00", "type": "Email", "status": "Phishing", "risk_score": 92},
        {"id": 2, "date": "2026-11-02 14:30", "type": "URL", "status": "Legitimate", "risk_score": 12},
    ]

def mock_save_scan(scan_type: str, status: str, risk_score: int):
    return True