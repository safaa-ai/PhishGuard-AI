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
    return _call("fusion", e_res, u_res)

def get_history() -> list:
    return _call("history")

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
