import pickle
from pathlib import Path

from .url_features import extract_url_features


BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = BASE_DIR / "models" / "url_model.pkl"

_model_bundle = None


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
        reasons.append(
            "Uses an IP address instead of a domain name"
        )

    if feature_map["url_length"] > 75:
        reasons.append("URL is unusually long")

    if feature_map["has_at"]:
        reasons.append("Contains @ symbol")

    if feature_map["has_shortener"]:
        reasons.append("Uses a URL shortening service")

    if feature_map["has_suspicious_keyword"]:
        reasons.append(
            "Contains suspicious login or security keywords"
        )

    if feature_map["uses_http"]:
        reasons.append("Uses HTTP instead of HTTPS")

    if feature_map["has_suspicious_tld"]:
        reasons.append(
            "Uses a TLD associated with suspicious URLs"
        )

    if feature_map["subdomain_count"] >= 3:
        reasons.append("Contains multiple subdomains")

    if feature_map["hyphen_count"] >= 2:
        reasons.append(
            "Contains multiple hyphens in the domain"
        )

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

    prediction = int(model.predict([features])[0])

    probabilities = model.predict_proba([features])[0]

    class_index = list(model.classes_).index(prediction)

    confidence = float(probabilities[class_index])

    reasons = get_reasons(features, feature_names)

    if prediction == 1:
        status = "Phishing"

        if not reasons:
            reasons.append(
                "The machine learning model classified this URL "
                "as phishing, although no listed rule-based "
                "indicator was detected."
            )

    else:
        status = "Safe"

        if not reasons:
            reasons.append(
                "No listed suspicious URL indicators were detected."
            )

    return {
        "status": status,
        "confidence": round(confidence, 2),
        "reasons": reasons,
        "model_prediction": status,
        "reputation_status": "Not checked",
        "warning": (
            "This result is based on the trained machine learning "
            "model and URL features only. No external reputation "
            "or threat-intelligence service was checked. "
            "A Safe result does not guarantee that the URL is safe."
        )
    }