import os
import re
import joblib
import numpy as np

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "models", "email_model.pkl")

_model = None


def _clean_text(text: str) -> str:
    text = str(text).lower()
    text = re.sub(r"http\S+|www\.\S+", " url ", text)
    text = re.sub(r"\S+@\S+", " email ", text)
    text = re.sub(r"<.*?>", " ", text)
    text = re.sub(r"[^a-z\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _load_model():
    global _model
    if _model is None:
        _model = joblib.load(MODEL_PATH)
    return _model


def analyze_email(text: str) -> dict:
    if not text or not text.strip():
        raise ValueError("Email text cannot be empty.")

    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            f"Email model not found: {MODEL_PATH}"
        )

    model = _load_model()
    tfidf = model.named_steps["tfidf"]
    clf = model.named_steps["clf"]

    clean = _clean_text(text)
    vec = tfidf.transform([clean])

    proba = clf.predict_proba(vec)[0]
    classes = list(clf.classes_)
    phishing_index = classes.index(1)
    phishing_prob = float(proba[phishing_index])
    is_phishing = phishing_prob >= 0.5

    feature_names = np.array(tfidf.get_feature_names_out())
    contributions = vec.toarray()[0] * clf.coef_[0]
    top_idx = contributions.argsort()[::-1][:5]
    suspicious = [
        feature_names[i]
        for i in top_idx
        if contributions[i] > 0
    ]

    return {
        "status": "Phishing" if is_phishing else "Legitimate",
        "confidence": round(
            phishing_prob if is_phishing else 1 - phishing_prob, 2
        ),
        "suspicious_words": suspicious if is_phishing else [],
    }