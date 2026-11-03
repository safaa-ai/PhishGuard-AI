
def calculate_risk(result):
    status = result["status"].lower()
    confidence = float(result["confidence"])

    if confidence > 1:
        confidence = confidence / 100

    if not 0 <= confidence <= 1:
        raise ValueError("Confidence must be between 0 and 1.")

    if status in ["phishing", "malicious", "unsafe"]:
        risk_score = confidence * 100

    elif status in ["legitimate", "safe", "benign"]:
        risk_score = (1 - confidence) * 100

    else:
        raise ValueError(f"Unknown status: {status}")

    return round(risk_score, 2)

def get_risk_level(risk_score):

    if risk_score < 30:
        return "Low"

    elif risk_score < 70:
        return "Medium"

    else:
        return "High"

def fuse_threats(email_result=None, url_result=None):

    scores = []

    if email_result is not None:
        email_score = calculate_risk(email_result)
        scores.append(email_score)

    if url_result is not None:
        url_score = calculate_risk(url_result)
        scores.append(url_score)

    if not scores:
        raise ValueError("At least one analysis result is required.")

    risk_score = round(sum(scores) / len(scores), 2)

    risk_level = get_risk_level(risk_score)

    return {
        "risk_score": risk_score,
        "risk_level": risk_level
    }

def collect_reasons(email_result=None, url_result=None):

    reasons = []

    if email_result is not None:
        if email_result["status"].lower() == "phishing":
            suspicious_words = email_result.get("suspicious_words", [])

            if suspicious_words:
                reasons.append(
                    "Suspicious email words: "
                    + ", ".join(suspicious_words)
                )

    if url_result is not None:
        if url_result["status"].lower() == "phishing":
            url_reasons = url_result.get("reasons", [])
            reasons.extend(url_reasons)

    return reasons

def get_recommendations(risk_level):

    if risk_level == "High":
        return [
            "Do not click suspicious links.",
            "Do not share passwords or personal information.",
            "Report the suspicious email."
        ]

    elif risk_level == "Medium":
        return [
            "Check the sender's email address.",
            "Verify links before opening them.",
            "Be careful when sharing personal information."
        ]

    else:
        return [
            "Continue following safe browsing practices.",
            "Keep your security software updated."
        ]

def analyze_threat(email_result=None, url_result=None):

    fusion_result = fuse_threats(email_result, url_result)

    reasons = collect_reasons(email_result, url_result)

    recommendations = get_recommendations(
        fusion_result["risk_level"]
    )

    return {
        "risk_score": fusion_result["risk_score"],
        "risk_level": fusion_result["risk_level"],
        "reasons": reasons,
        "recommendations": recommendations
    }
    
