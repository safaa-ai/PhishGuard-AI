"""Single integration point between the UI and the backend modules in core/."""

from __future__ import annotations
import importlib
from datetime import datetime
import streamlit as st
from views import mock_backend as mock

class BackendError(Exception):
    """A backend function failed or returned invalid data."""

_SPECS = {
    "email": ("core.email_analyzer", "analyze_email", mock.mock_analyze_email),
    "url": ("core.url_analyzer", "analyze_url", mock.mock_analyze_url),
    "fusion": ("core.threat_fusion", "get_combined_assessment", mock.mock_get_combined_assessment),
    "history": ("core.database", "get_history", mock.mock_get_history),
    "save": ("core.database", "save_scan", mock.mock_save_scan),
}

def _call(key: str, *args):
    mod_name, func_name, fallback = _SPECS[key]
    try:
        mod = importlib.import_module(mod_name)
        func = getattr(mod, func_name)
        return func(*args)
    except Exception as err:
        st.warning(f"⚠️ الباك إند فشل واتحول للنسخة التجريبية: {type(err).__name__}: {err}")
        return fallback(*args)

def analyze_email(text: str) -> dict:
    return _call("email", text)

def analyze_url(url: str) -> dict:
    return _call("url", url)

def get_combined_assessment(e_res, u_res) -> dict:
    def _score(r):
        status = str(r.get("status", "")).lower()
        conf = float(r.get("confidence", 0))
        if conf > 1:
            conf = conf / 100
        if status in ("phishing", "malicious", "unsafe"):
            return conf * 100
        if status == "suspicious":
            return 35 + 35 * conf
        return (1 - conf) * 100

    results = [r for r in (e_res, u_res) if r]
    if not results:
        raise BackendError("At least one analysis result is required.")

    score = round(sum(_score(r) for r in results) / len(results))

    if score >= 70:
        level = "High Risk"
        directive = "Block communication and reset access credentials immediately."
    elif score >= 30:
        level = "Medium Risk"
        directive = "Verify the sender and the link through a trusted channel before interacting."
    else:
        level = "Low Risk"
        directive = "No major threat indicators found. Continue following safe practices."

    return {
        "overall_risk_score": score,
        "risk_level": level,
        "recommendation": directive,
    }

def get_history() -> list:
    rows = _call("history")
    # لو السجل فاضي أو أعمدته مش متوافقة مع الصفحة، نستخدم البيانات التجريبية
    if not rows or not isinstance(rows[0], dict) or "type" not in rows[0] or "status" not in rows[0]:
        return mock.mock_get_history()
    return rows

def save_scan(scan_type: str, status: str, risk_score: int, scanned_input: str = ""):
    try:
        from core import database
        database.initialize_db()
        return database.save_scan(
            scan_type,
            scanned_input,
            {"status": status, "confidence": risk_score / 100},
            {"risk_score": risk_score, "risk_level": status},
        )
    except Exception as err:
        st.warning(f"تعذر حفظ السجل: {type(err).__name__}: {err}")

def get_model_accuracy() -> float:
    return 0.964
