# PhishGuard AI - Integration Contract

Core requirements for Members 1-3 to seamlessly hook into Member 4 frontend:

- `core/email_analyzer.py`: `analyze_email(text: str) -> dict`
- `core/url_analyzer.py`: `analyze_url(url: str) -> dict`
- `core/threat_fusion.py`: `get_combined_assessment(email_res, url_res) -> dict`
- `core/database.py`: `get_history() -> list` & `save_scan(scan_type, status, risk_score)`