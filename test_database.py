
from core.database import initialize_db, save_scan, get_history

initialize_db()

analysis_result = {
    "status": "Phishing",
    "confidence": 0.90
}

fusion_result = {
    "risk_score": 90.0,
    "risk_level": "High"
}

scan_id = save_scan(
    "Email",
    "Test phishing email",
    analysis_result,
    fusion_result
)

print("Saved scan ID:", scan_id)

history = get_history()

print("Scan History:")
print(history)
