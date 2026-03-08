import sqlite3
import json
from datetime import datetime
import os

DB_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(DB_DIR, "db.sqlite")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            status TEXT NOT NULL,
            reasons TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def log_scan(url, risk_score, status, reasons):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scans (url, risk_score, status, reasons, timestamp)
        VALUES (?, ?, ?, ?, ?)
    """, (url, risk_score, status, json.dumps(reasons), datetime.utcnow().isoformat(timespec='seconds')))
    conn.commit()
    conn.close()

def get_recent_scans(limit=50):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, url, risk_score, status, reasons, timestamp
        FROM scans ORDER BY id DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [
        {
            "id": r[0], "url": r[1], "risk_score": r[2],
            "status": r[3], "reasons": json.loads(r[4]), "timestamp": r[5]
        }
        for r in rows
    ]
