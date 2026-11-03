"""Dashboard & Audit Log Analytics."""

import pandas as pd
import plotly.express as px
import streamlit as st
from views import ui_components as ui
from views.backend import BackendError, get_history

STATUS_COLORS = {"Phishing": ui.RED, "Suspicious": ui.AMBER, "Legitimate": ui.GREEN}

def render():
    ui.page_header("Audit Logs & Analytics", "Historical threat monitoring and reporting")
    try:
        data = get_history()
    except BackendError as exc:
        st.error(f"Failed to fetch log history: {exc}")
        return

    if not data:
        st.info("No recorded scan logs available.")
        return

    df = pd.DataFrame(data)
    
    m1, m2, m3 = st.columns(3)
    m1.metric("Total Scans", len(df))
    m2.metric("Critical Threats", int((df["status"] == "Phishing").sum()))
    m3.metric("Avg Risk Index", f"{df['risk_score'].mean():.1f}")

    st.markdown("<div style='height:1rem'></div>", unsafe_allow_html=True)
    c1, c2 = st.columns(2)
    with c1:
        pie = px.pie(df, names="status", title="Threat Class Distribution", color="status", color_discrete_map=STATUS_COLORS)
        st.plotly_chart(ui.style_fig(pie), use_container_width=True)
    with c2:
        bar = px.histogram(df, x="type", color="status", title="Vectors Analyzed", color_discrete_map=STATUS_COLORS, barmode="group")
        st.plotly_chart(ui.style_fig(bar), use_container_width=True)

    st.markdown("##### Recorded Events")
    st.dataframe(df, use_container_width=True, hide_index=True)