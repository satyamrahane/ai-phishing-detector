from flask import Blueprint, request, jsonify
from detector import analyze_url
import datetime

scan_route = Blueprint("scan_route", __name__)

# In-memory log storage
scan_logs = []

@scan_route.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    
    # Error handling if URL is missing
    if not data or "url" not in data:
        return jsonify({"error": "URL is required"}), 400

    url = data["url"]

    result = analyze_url(url)
    
    log_entry = {
        "url": url,
        "risk_score": result["risk_score"],
        "status": result["status"],
        "timestamp": datetime.datetime.now().isoformat()
    }
    scan_logs.append(log_entry)

    return jsonify(result)
