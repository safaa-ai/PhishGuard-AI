"""Knowledge Base & Awareness Module."""

import streamlit as st
from views import ui_components as ui

QUESTIONS = [
    {
        "q": "What is the primary indicator of domain typosquatting in phishing emails?",
        "options": [
            "Use of standard HTTP protocol",
            "Homoglyph substitution (e.g., paypa1.com vs paypal.com)",
            "Presence of DKIM signatures",
            "Long email body length",
        ],
        "answer": 1,
        "explain": "Attackers substitute visually similar characters to mimic legitimate enterprise domains.",
    },
    {
        "q": "How should an organization handle an unexpected double-extension attachment (e.g., report.pdf.exe)?",
        "options": [
            "Open with an isolated viewer",
            "Rename the file to remove the secondary extension",
            "Quarantine immediately at email gateway",
            "Forward to accounting for confirmation",
        ],
        "answer": 2,
        "explain": "Double extensions hide executable binaries behind recognized non-executable file types.",
    },
]

def render():
    ui.page_header("Security Knowledge Base", "Awareness evaluation and threat indicators")
    
    for idx, q in enumerate(QUESTIONS, start=1):
        st.markdown(f"**Q{idx}. {q['q']}**")
        opt = st.radio(f"Select answer for Q{idx}", q["options"], key=f"q_{idx}", label_visibility="collapsed")
        if st.button(f"Validate Q{idx}", key=f"v_{idx}"):
            if opt == q["options"][q["answer"]]:
                st.success(f"Correct: {q['explain']}")
            else:
                st.error(f"Incorrect: {q['explain']}")
        st.markdown("---")