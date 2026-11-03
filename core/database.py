
import sqlite3
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = BASE_DIR / "data"

DB_PATH = DATA_DIR / "phishguard.db"


def initialize_db():

    DATA_DIR.mkdir(exist_ok=True)

    connection = sqlite3.connect(DB_PATH)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT NOT NULL,
            scanned_input TEXT NOT NULL,
            status TEXT,
            confidence REAL,
            risk_score REAL,
            risk_level TEXT,
            details_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.commit()

    connection.close()



def save_scan(scan_type, scanned_input, analysis_result, fusion_result=None):

    import json

    connection = sqlite3.connect(DB_PATH)

    cursor = connection.cursor()

    details = {
        "analysis_result": analysis_result,
        "fusion_result": fusion_result
    }

    status = analysis_result.get("status")
    confidence = analysis_result.get("confidence")

    risk_score = None
    risk_level = None

    if fusion_result is not None:
        risk_score = fusion_result.get("risk_score")
        risk_level = fusion_result.get("risk_level")

    cursor.execute("""
        INSERT INTO scans (
            scan_type,
            scanned_input,
            status,
            confidence,
            risk_score,
            risk_level,
            details_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_type,
        scanned_input,
        status,
        confidence,
        risk_score,
        risk_level,
        json.dumps(details, ensure_ascii=False)
    ))

    scan_id = cursor.lastrowid

    connection.commit()
    connection.close()

    return scan_id

def get_history(limit=50):

    import json

    connection = sqlite3.connect(DB_PATH)

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
        SELECT * FROM scans
        ORDER BY created_at DESC
        LIMIT ?
    """, (limit,))

    rows = cursor.fetchall()

    history = []

    for row in rows:

        scan = dict(row)

        scan["details"] = json.loads(
            scan["details_json"]
        )

        history.append(scan)

    connection.close()

    return history
