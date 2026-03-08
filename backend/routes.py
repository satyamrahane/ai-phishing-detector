from flask import Blueprint, request, jsonify, Response
from detector import analyze_url
import datetime
import sys
import os
import sqlite3
import csv
import io
import json
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Add parent dir to path so we can import from database/
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database.db import get_recent_scans, log_scan, DB_PATH

scan_route = Blueprint("scan_route", __name__)
limiter = Limiter(key_func=get_remote_address)


# ──────────────────────────────────────────────
# POST /scan  →  Analyse a URL and log the result
# ──────────────────────────────────────────────
@scan_route.route("/scan", methods=["POST"])
@limiter.limit("30 per minute")
def scan():
    data = request.get_json()

    # Input sanitization
    if not data or "url" not in data:
        return jsonify({"error": "URL is required"}), 400
        
    url = data["url"]
    if not isinstance(url, str):
        return jsonify({"error": "URL must be a string"}), 400
        
    if len(url) > 2000:
        return jsonify({"error": "URL exceeds maximum length of 2000 characters"}), 400

    result = analyze_url(url)

    # Log to SQLite database
    log_scan(url, result["risk_score"], result["status"], result["reasons"])

    return jsonify(result)


# ──────────────────────────────────────────────
# GET /logs  →  Return latest scan logs and stats
# ──────────────────────────────────────────────
@scan_route.route("/logs", methods=["GET"])
@limiter.limit("60 per minute")
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
# GET /export  →  Download logs as CSV
# ──────────────────────────────────────────────
@scan_route.route("/export", methods=["GET"])
@limiter.limit("20 per minute")
def export_csv():
    # We fetch a large limit to represent "all scans"
    scans = get_recent_scans(limit=10000)
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "url", "risk_score", "status", "reasons", "timestamp"])
    
    for s in scans:
        writer.writerow([
            s["id"], 
            s["url"], 
            s["risk_score"], 
            s["status"], 
            json.dumps(s["reasons"]), 
            s["timestamp"]
        ])
        
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=scans_export.csv"}
    )


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
