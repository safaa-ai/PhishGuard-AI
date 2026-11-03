"""Scanner Pages - Multi-vector inspection tools."""

import html
import plotly.graph_objects as go
import streamlit as st
from views import ui_components as ui
from views.backend import BackendError, analyze_email, analyze_url, get_combined_assessment, save_scan

SAMPLE_EMAIL = (
    "Subject: URGENT - Security Verification Required\n\n"
    "Dear Customer, unusual activity was detected on your account. Access has been restricted until "
    "identity verification is complete. Click the link below immediately to unlock your account: "
    "http://secure-login.paypal.account.verify.bit.ly/update"
)
SAMPLE_URL = "http://secure-login.paypal.account.verify.bit.ly/update"

RECOMMENDATIONS = {
    "High Risk": {
        "en": [
            "Block sender address and flag domain at mail gateway.",
            "Do NOT interact with links or download attachments.",
            "Initiate credential revocation if user interaction occurred.",
        ],
        "ar": [
            "حظر عنوان المرسل وتصفية النطاق على بوابة البريد الإلكتروني.",
            "عدم التفاعل مع الرابط أو تنزيل أي مرفقات.",
            "إعادة تعيين كلمات المرور فوراً في حال إدخال البيانات.",
        ],
    },
    "Medium Risk": {
        "en": [
            "Verify origin via secondary authenticated channel.",
            "Inspect URL query parameters and SSL certificate issuer.",
            "Avoid entering administrative or financial credentials.",
        ],
        "ar": [
            "التحقق من مصدر الرسالة عبر قناة اتصل معتمدة.",
            "فحص شهادة الأمان والنطاق بشكل يدوي.",
            "تجنب إدخال أي بيانات حساسة.",
        ],
    },
    "Low Risk": {
        "en": [
            "No high-severity indicators detected.",
            "Standard security hygiene applies.",
        ],
        "ar": [
            "لم يتم رصد أي مؤشرات خطورة عالي المستوى.",
            "يرجى اتباع قواعد الأمان الرقمي الروتينية.",
        ],
    },
}

def _init_state():
    for key in ("email_result", "email_text_scanned", "url_result", "url_scanned", "combined_result"):
        st.session_state.setdefault(key, None)

def _email_tab():
    st.markdown("##### Input Raw Email Payload")
    email_text = st.text_area(
        "Email Content",
        key="email_input_field",
        height=200,
        placeholder="Paste full raw email headers and body content...",
        label_visibility="collapsed",
    )
    c1, c2, c3 = st.columns([1.5, 1, 1])
    analyze = c1.button("Execute Email Scan", type="primary", use_container_width=True)
    if c2.button("Load Sample Data", use_container_width=True):
        st.session_state["email_result"] = None
        analyze = True
        email_text = SAMPLE_EMAIL

    if analyze and email_text.strip():
        try:
            with st.spinner("Executing ML Analysis..."):
                res = analyze_email(email_text)
                st.session_state["email_result"] = res
                st.session_state["email_text_scanned"] = email_text
                save_scan("Email", res["status"], ui.result_to_score(res))
        except BackendError as err:
            st.error(f"Analysis Engine Error: {err}")

    res = st.session_state.get("email_result")
    if res:
        st.markdown("---")
        color, lbl = ui.style_for(res["status"])
        st.markdown(f"**Classification Status:** <span style='color:{color}; font-weight:700;'>{lbl}</span>", unsafe_allow_html=True)
        st.progress(res["confidence"], text=f"Model Confidence Level: {res['confidence']:.0%}")
        
        words = res.get("suspicious_words", [])
        if words:
            st.markdown("##### Flagged Indicators")
            st.markdown(ui.chips(words, "red"), unsafe_allow_html=True)
            st.markdown("##### Inspection Preview")
            st.markdown(
                f'<div style="background:#0B1120; border:1px solid #334155; padding:12px; border-radius:8px; font-family:monospace; font-size:0.85rem; color:#CBD5E1;">'
                f'{ui.highlight_text(st.session_state["email_text_scanned"], words)}</div>',
                unsafe_allow_html=True,
            )

def _url_tab():
    st.markdown("##### Input Target URL")
    url_text = st.text_input(
        "Target URL",
        key="url_input_field",
        placeholder="https://example.com/login",
        label_visibility="collapsed",
    )
    c1, c2 = st.columns([1.5, 1])
    scan = c1.button("Execute URL Inspection", type="primary", use_container_width=True)

    if scan and url_text.strip():
        try:
            with st.spinner("Running Heuristic Analysis..."):
                res = analyze_url(url_text)
                st.session_state["url_result"] = res
                st.session_state["url_scanned"] = url_text
                save_scan("URL", res["status"], ui.result_to_score(res))
        except BackendError as err:
            st.error(f"Inspection Error: {err}")

    res = st.session_state.get("url_result")
    if res:
        st.markdown("---")
        color, lbl = ui.style_for(res["status"])
        st.markdown(f"**Inspection Verdict:** <span style='color:{color}; font-weight:700;'>{lbl}</span>", unsafe_allow_html=True)
        reasons = res.get("reasons", [])
        if reasons:
            st.markdown("##### Heuristic Findings")
            for r in reasons:
                st.markdown(f"- <span style='color:#FCA5A5;'>{html.escape(r)}</span>", unsafe_allow_html=True)

def _combined_tab():
    e_res = st.session_state.get("email_result")
    u_res = st.session_state.get("url_result")

    if not e_res and not u_res:
        st.info("Execute an Email or URL scan to enable threat correlation.")
        return

    if st.button("Correlate Threat Signals", type="primary", use_container_width=True):
        try:
            comb = get_combined_assessment(e_res, u_res)
            st.session_state["combined_result"] = comb
            save_scan("Combined", ui.LEVEL_TO_STATUS.get(comb["risk_level"], "Suspicious"), comb["overall_risk_score"])
        except BackendError as err:
            st.error(f"Threat Fusion Error: {err}")

    comb = st.session_state.get("combined_result")
    if comb:
        st.markdown("---")
        score = comb["overall_risk_score"]
        level = comb["risk_level"]
        color = ui.style_for(level)[0]

        st.markdown(f"### Unified Risk Score: <span style='color:{color};'>{score} / 100</span> ({level})", unsafe_allow_html=True)
        st.markdown(f"**Primary Directive:** {comb.get('recommendation', '')}")

        recs = RECOMMENDATIONS.get(level, RECOMMENDATIONS["Medium Risk"])
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("##### Actionable Steps (EN)")
            for step in recs["en"]:
                st.markdown(f"- {step}")
        with col2:
            st.markdown("##### إرشادات الاستجابة (AR)")
            for step in recs["ar"]:
                st.markdown(f"- {step}")

def render():
    st.markdown("""
    <style>
    /* تعديل لون الكتابة داخل صناديق إدخال النصوص والـ Text Area ليصبح واضحاً وسلساً */
    .stTextInput input, .stTextArea textarea {
        color: #000000 !important;
        background-color: #ffffff !important;
    }
    </style>
""", unsafe_allow_html=True)
    _init_state()
    ui.page_header("Threat Scanner", "Automated analysis across multiple payload channels")
    t1, t2, t3 = st.tabs(["Email Analysis", "URL Inspection", "Threat Correlation"])
    with t1: _email_tab()
    with t2: _url_tab()
    with t3: _combined_tab()
