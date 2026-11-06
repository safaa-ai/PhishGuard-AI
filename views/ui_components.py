"""Enterprise UI Helpers & Formatting Utilities."""

from __future__ import annotations
import html
import re
import streamlit as st

PAGE_HOME = "Overview"
PAGE_SCANNER = "Threat Scanner"
PAGE_DASHBOARD = "Analytics & Logs"
PAGE_QUIZ = "Knowledge Base"
NAV_KEY = "nav_page"

RED = "#EF4444"
AMBER = "#F59E0B"
GREEN = "#10B981"
CYAN = "#0EA5E9"

STATUS_MAP = {
    "Phishing": (RED, "High Risk / Phishing Detected"),
    "Suspicious": (AMBER, "Medium Risk / Suspicious"),
    "Legitimate": (GREEN, "Low Risk / Clean"),
    "Safe": (GREEN, "Low Risk / Clean"),
    "High Risk": (RED, "High Risk Level"),
    "Medium Risk": (AMBER, "Medium Risk Level"),
    "Low Risk": (GREEN, "Low Risk Level"),
}

LEVEL_TO_STATUS = {
    "High Risk": "Phishing",
    "Medium Risk": "Suspicious",
    "Low Risk": "Legitimate",
}

STATUS_TO_LEVEL = {
    "Phishing": "High Risk",
    "Suspicious": "Medium Risk",
    "Legitimate": "Low Risk",
}

def goto(page: str) -> None:
    st.session_state[NAV_KEY] = page

def style_for(status: str) -> tuple[str, str]:
    return STATUS_MAP.get(status, (AMBER, str(status)))

def risk_level_label(score: float) -> str:
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"

def result_to_score(result: dict | None) -> int:
    if not result:
        return 0
    confidence = float(result.get("confidence", 0))
    status = result.get("status")
    if status == "Phishing":
        return round(confidence * 100)
    if status == "Suspicious":
        return round(35 + 35 * confidence)
    return round((1 - confidence) * 100)

def page_header(title: str, subtitle: str = "") -> None:
    sub = f'<div style="color:#94A3B8; font-size:0.9rem; margin-top:0.2rem; margin-bottom:1.2rem;">{html.escape(subtitle)}</div>' if subtitle else ""
    st.markdown(
        f'<div style="margin-bottom:0.8rem;"><h2 style="font-size:1.5rem; font-weight:700; margin:0; color:#F8FAFC;">{html.escape(title)}</h2>{sub}</div>',
        unsafe_allow_html=True,
    )

def stat_card(label: str, value: str, accent: str = CYAN) -> str:
    return (
        f'<div class="pg-stat-card" style="--accent-color:{accent};">'
        f'<div class="pg-stat-val">{html.escape(value)}</div>'
        f'<div class="pg-stat-lbl">{html.escape(label)}</div>'
        f'</div>'
    )

def chips(words: list[str], kind: str = "red") -> str:
    if not words:
        return ""
    color_map = {
        "red": ("rgba(239, 68, 68, 0.15)", "#FCA5A5", "#EF4444"),
        "amber": ("rgba(245, 158, 11, 0.15)", "#FCD34D", "#F59E0B"),
        "green": ("rgba(16, 185, 129, 0.15)", "#6EE7B7", "#10B981"),
        "cyan": ("rgba(14, 165, 233, 0.15)", "#7DD3FC", "#0EA5E9"),
    }
    bg, fg, border = color_map.get(kind, color_map["cyan"])
    items = "".join([
        f'<span style="background:{bg}; color:{fg}; border:1px solid {border}; padding:3px 10px; border-radius:9999px; font-size:0.8rem; font-weight:500; margin-right:6px; margin-bottom:6px; display:inline-block;">{html.escape(w)}</span>'
        for w in words
    ])
    return f'<div style="margin:8px 0;">{items}</div>'

def card(icon: str, title: str, body: str) -> str:
    return (
        f'<div class="pg-card">'
        f'<div style="font-size:1.1rem; font-weight:700; color:#F8FAFC; margin-bottom:6px;">{html.escape(title)}</div>'
        f'<div style="color:#94A3B8; font-size:0.88rem; line-height:1.5;">{html.escape(body)}</div>'
        f'</div>'
    )

def highlight_text(text: str, words: list[str], limit: int = 1500) -> str:
    snippet = text[:limit] + ("..." if len(text) > limit else "")
    escaped = html.escape(snippet)
    if words:
        pattern = "|".join(re.escape(html.escape(w)) for w in sorted(set(words), key=len, reverse=True))
        escaped = re.sub(
            pattern,
            lambda m: f'<mark style="background:rgba(239,68,68,0.25); color:#FCA5A5; padding:2px 4px; border-radius:4px; border-bottom:1px solid #EF4444;">{m.group(0)}</mark>',
            escaped,
            flags=re.IGNORECASE,
        )
    return escaped.replace("\n", "<br>")

def style_fig(fig, height: int = 320):
    fig.update_layout(
        height=height,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#F8FAFC", family="Inter, sans-serif"),
        margin=dict(l=10, r=10, t=30, b=10),
        legend=dict(bgcolor="rgba(0,0,0,0)"),
    )
    return fig
