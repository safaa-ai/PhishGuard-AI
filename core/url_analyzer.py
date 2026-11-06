import pickle
from pathlib import Path
from urllib.parse import urlsplit

from .url_features import extract_url_features


BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = BASE_DIR / "models" / "url_model.pkl"

_model_bundle = None

TRUSTED_DOMAINS = {
    "google.com", "github.com", "wikipedia.org", "youtube.com",
    "microsoft.com", "apple.com", "amazon.com", "facebook.com",
    "linkedin.com", "stackoverflow.com", "python.org", "streamlit.io",
}


def _is_trusted(url):
    test_url = url if "://" in url else "https://" + url
    host = (urlsplit(test_url).hostname or "").lower()
    return any(host == d or host.endswith("." + d) for d in TRUSTED_DOMAINS)


def load_model():
    global _model_bundle

    if _model_bundle is None:
        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                f"URL model not found: {MODEL_PATH}"
            )

        with open(MODEL_PATH, "rb") as file:
            _model_bundle = pickle.load(file)

    return _model_bundle


def get_reasons(features, feature_names):

    reasons = []

    feature_map = dict(zip(feature_names, features))

    if feature_map["has_ip"]:
        reasons.append("Uses an IP address instead of a domain name")

    if feature_map["url_length"] > 75:
        reasons.append("URL is unusually long")

    if feature_map["has_at"]:
        reasons.append("Contains @ symbol")

    if feature_map["has_shortener"]:
        reasons.append("Uses a URL shortening service")

    if feature_map["has_suspicious_keyword"]:
        reasons.append("Contains suspicious login or security keywords")

    if feature_map["uses_http"]:
        reasons.append("Uses HTTP instead of HTTPS")

    if feature_map["has_suspicious_tld"]:
        reasons.append("Uses a TLD associated with suspicious URLs")

    if feature_map["subdomain_count"] >= 3:
        reasons.append("Contains multiple subdomains")

    if feature_map["hyphen_count"] >= 2:
        reasons.append("Contains multiple hyphens in the domain")

    if feature_map["digit_count"] >= 5:
        reasons.append("Contains many digits")

    return reasons


def analyze_url(url: str) -> dict:

    if not isinstance(url, str) or not url.strip():
        raise ValueError("Please enter a valid URL.")

    model_bundle = load_model()
    model = model_bundle["model"]
    feature_names = model_bundle["feature_names"]

    features = extract_url_features(url)
    probabilities = model.predict_proba([features])[0]
    phishing_prob = float(probabilities[list(model.classes_).index(1)])

    reasons = get_reasons(features, feature_names)

    if _is_trusted(url) and not reasons:
        status = "Legitimate"
        confidence = 0.95
        reasons.append("Domain is on the trusted websites list.")
    elif phishing_prob >= 0.85:
        status = "Phishing"
        confidence = phishing_prob
    elif phishing_prob >= 0.5:
        status = "Suspicious"
        confidence = phishing_prob
        if not reasons:
            reasons.append(
                "The model found this URL somewhat unusual, "
                "but no clear indicator was detected."
            )
    else:
        status = "Legitimate"
        confidence = 1 - phishing_prob
        if not reasons:
            reasons.append("No listed suspicious URL indicators were detected.")

    return {
        "status": status,
        "confidence": round(confidence, 2),
        "reasons": reasons,
        "model_prediction": status,
        "reputation_status": "Trusted list checked",
        "warning": (
            "This result is based on a machine learning model, URL features, "
            "and a small trusted-domain list. A Legitimate result does not "
            "guarantee that the URL is safe."
        ),
    }
