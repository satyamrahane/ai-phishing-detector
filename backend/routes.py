from flask import Blueprint, request, jsonify
from detector import analyze_url
import datetime

scan_route = Blueprint("scan_route", __name__)

# In-memory log storage — persists for the lifetime of the server process
# Capped at MAX_LOGS entries; oldest entry is dropped when the cap is reached
MAX_LOGS = 50
scan_logs = []


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

    # Build log entry with all required fields
    log_entry = {
        "url": url,
        "risk_score": result["risk_score"],
        "status": result["status"],
        # ISO-8601 timestamp without microseconds: e.g. "2026-03-08T15:30:00"
        "timestamp": datetime.datetime.now().isoformat(timespec="seconds")
    }
    # Enforce the rolling cap — drop the oldest entry if needed
    if len(scan_logs) >= MAX_LOGS:
        scan_logs.pop(0)
    scan_logs.append(log_entry)

    return jsonify(result)


# ──────────────────────────────────────────────
# GET /logs  →  Return latest scan logs (newest first, max 50)
# ──────────────────────────────────────────────
@scan_route.route("/logs", methods=["GET"])
def get_logs():
    # Return a plain JSON array, newest scan first, capped at MAX_LOGS
    latest = list(reversed(scan_logs[-MAX_LOGS:]))
    return jsonify(latest)


# ──────────────────────────────────────────────
# DELETE /logs  →  Clear all scan logs
# ──────────────────────────────────────────────
@scan_route.route("/logs", methods=["DELETE"])
def clear_logs():
    scan_logs.clear()
    return jsonify({"message": "Scan logs cleared successfully"})
