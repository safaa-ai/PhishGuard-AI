
from core.threat_fusion import analyze_threat

email_result = {
    "status": "Phishing",
    "confidence": 0.90,
    "suspicious_words": ["password", "urgent"]
}

url_result = {
    "status": "Safe",
    "confidence": 0.90,
    "reasons": []
}

result = analyze_threat(email_result, url_result)

print(result)
