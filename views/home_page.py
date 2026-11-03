"""Home Page - Threat Overview."""

import streamlit as st
from views import ui_components as ui
from views.backend import BackendError, get_history, get_model_accuracy

def render() -> None:
    ui.page_header("Threat Intelligence Platform", "Enterprise phishing detection and proactive risk mitigation")

    try:
        history = get_history()
    except BackendError as exc:
        history = []
        st.warning(f"Unable to access log data: {exc}")

    total = len(history)
    threats = sum(1 for item in history if item["status"] in ("Phishing", "Suspicious"))
    accuracy = get_model_accuracy()

    c1, c2, c3 = st.columns(3)
    c1.markdown(ui.stat_card("Total Scans Processed", f"{total:,}", ui.CYAN), unsafe_allow_html=True)
    c2.markdown(ui.stat_card("Threats Identified", f"{threats:,}", ui.RED), unsafe_allow_html=True)
    c3.markdown(ui.stat_card("Model Precision", f"{accuracy:.1%}", ui.GREEN), unsafe_allow_html=True)

    st.markdown("<div style='height:1.5rem'></div>", unsafe_allow_html=True)
    ui.page_header("Platform Capabilities", "Core security analysis engines")

    features = [
        ("Email Security", "ML-driven classification engine for inspecting email bodies, headers, and payload syntax.", ui.PAGE_SCANNER, "Access Scanner"),
        ("URL Heuristics", "Deep inspection of domain reputation, suspicious TLDs, redirect chains, and typosquatting.", ui.PAGE_SCANNER, "Access Scanner"),
        ("Threat Fusion", "Correlation of multi-source indicators into a unified score with actionable mitigation steps.", ui.PAGE_SCANNER, "View Assessment"),
        ("Knowledge Base", "Security awareness training modules and simulation benchmarks for operational readiness.", ui.PAGE_QUIZ, "Launch Module"),
    ]

    cols = st.columns(4)
    for idx, (col, (title, body, page, label)) in enumerate(zip(cols, features)):
        with col:
            st.markdown(ui.card("", title, body), unsafe_allow_html=True)
            st.button(label, key=f"home_btn_{idx}", on_click=ui.goto, args=(page,), use_container_width=True)