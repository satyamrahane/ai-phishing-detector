from flask import Blueprint, request, jsonify
from detector import analyze_url
import datetime
import sys
import os
import sqlite3

# Add parent dir to path so we can import from database/
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database.db import get_recent_scans, log_scan, DB_PATH

scan_route = Blueprint("scan_route", __name__)


# ──────────────────────────────────────────────
# POST /scan  →  Analyse a URL and log the result
# ──────────────────────────────────────────────
@scan_route.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()

    # Error handling if URL is missing
    if not data or "url" not in data:
        return jsonify({"error": "URL is required"}), 400

    url = data["url"]

    result = analyze_url(url)

    # Log to SQLite database
    log_scan(url, result["risk_score"], result["status"], result["reasons"])

    return jsonify(result)


# ──────────────────────────────────────────────
# GET /logs  →  Return latest scan logs and stats
# ──────────────────────────────────────────────
@scan_route.route("/logs", methods=["GET"])
def get_logs():
    scans = get_recent_scans(limit=50)
    total = len(scans)
    phishing = sum(1 for s in scans if s["status"] == "Phishing")
    suspicious = sum(1 for s in scans if s["status"] == "Suspicious")
    safe = sum(1 for s in scans if s["status"] == "Safe")

    return jsonify({
        "total_scans": total,
        "phishing_count": phishing,
        "suspicious_count": suspicious,
        "safe_count": safe,
        "scans": scans
    })


# ──────────────────────────────────────────────
# DELETE /logs  →  Clear all scan logs
# ──────────────────────────────────────────────
@scan_route.route("/logs", methods=["DELETE"])
def clear_logs():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scans")
    conn.commit()
    conn.close()
    return jsonify({"message": "Scan logs cleared successfully"})
