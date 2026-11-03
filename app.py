"""
PhishGuard AI - Main Application Entry Point
Enterprise-grade Cybersecurity Interface
"""

import streamlit as st

st.set_page_config(
    page_title="PhishGuard AI | Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

from views import backend, dashboard_page, home_page, quiz_page, scanner_pages  # noqa: E402
from views.ui_components import (  # noqa: E402
    NAV_KEY,
    PAGE_DASHBOARD,
    PAGE_HOME,
    PAGE_QUIZ,
    PAGE_SCANNER,
)

ENTERPRISE_THEME = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

:root {
  --bg-dark: #0F172A;
  --panel-bg: #1E293B;
  --panel-hover: #26334D;
  --border-color: #334155;
  --accent-cyan: #0EA5E9;
  --accent-blue: #2563EB;
  --danger-red: #EF4444;
  --warning-amber: #F59E0B;
  --success-green: #10B981;
  --text-main: #F8FAFC;
  --text-muted: #94A3B8;
  --radius-lg: 12px;
  --radius-md: 8px;
}

html, body, .stApp, [class*="css"] {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
}

.stApp {
    background-color: var(--bg-dark);
    color: var(--text-main);
}

header[data-testid="stHeader"] { background: transparent; }
.block-container { padding-top: 1.5rem; padding-bottom: 2rem; max-width: 1280px; }

/* Sidebar styling */
section[data-testid="stSidebar"] {
    background-color: #0B1120;
    border-right: 1px solid var(--border-color);
}
section[data-testid="stSidebar"] .block-container { padding-top: 1.5rem; }

.pg-brand-container {
    padding: 0.5rem 0.5rem 1.5rem 0.5rem;
    border-bottom: 1px solid var(--border-color);
    margin-bottom: 1rem;
}
.pg-brand-title {
    font-size: 1.25rem;
    font-weight: 700;
    color: #FFFFFF;
    letter-spacing: -0.02em;
}
.pg-brand-title span { color: var(--accent-cyan); }
.pg-brand-sub {
    font-size: 0.75rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-top: 0.2rem;
}

/* Cards & Layout */
.pg-card {
    background: var(--panel-bg);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-lg);
    padding: 1.25rem;
    height: 100%;
}
.pg-stat-card {
    background: var(--panel-bg);
    border: 1px solid var(--border-color);
    border-left: 4px solid var(--accent-color, var(--accent-cyan));
    border-radius: var(--radius-md);
    padding: 1rem 1.2rem;
}
.pg-stat-val {
    font-size: 1.8rem;
    font-weight: 700;
    color: var(--text-main);
    line-height: 1.2;
}
.pg-stat-lbl {
    font-size: 0.78rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-top: 0.2rem;
}

/* UI Elements */
div[data-baseweb="textarea"], div[data-baseweb="input"] {
    border-radius: var(--radius-md) !important;
    background-color: #0B1120 !important;
}
.stButton>button {
    border-radius: var(--radius-md);
    font-weight: 500;
    transition: all 0.2s ease;
}
.stButton>button[kind="primary"] {
    background-color: var(--accent-cyan);
    color: #0F172A;
    border: none;
}
.stButton>button[kind="primary"]:hover {
    background-color: #38BDF8;
}
</style>
"""

def _render_sidebar():
    with st.sidebar:
        st.markdown(
            '<div class="pg-brand-container">'
            '<div class="pg-brand-title">Phish<span>Guard</span></div>'
            '<div class="pg-brand-sub">Threat Analysis Platform</div>'
            '</div>',
            unsafe_allow_html=True,
        )
        st.radio(
            "Navigation",
            [PAGE_HOME, PAGE_SCANNER, PAGE_DASHBOARD, PAGE_QUIZ],
            key=NAV_KEY,
            label_visibility="collapsed",
        )

def main():
    st.markdown(ENTERPRISE_THEME, unsafe_allow_html=True)
    if NAV_KEY not in st.session_state:
        st.session_state[NAV_KEY] = PAGE_HOME

    _render_sidebar()

    pages = {
        PAGE_HOME: home_page.render,
        PAGE_SCANNER: scanner_pages.render,
        PAGE_DASHBOARD: dashboard_page.render,
        PAGE_QUIZ: quiz_page.render,
    }
    pages[st.session_state[NAV_KEY]]()

if __name__ == "__main__":
    main()