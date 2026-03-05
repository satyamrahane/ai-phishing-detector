from flask import Blueprint, request, jsonify
from detector import analyze_url

scan_route = Blueprint("scan_route", __name__)

@scan_route.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    
    # Error handling if URL is missing
    if not data or "url" not in data:
        return jsonify({"error": "Missing 'url' parameter"}), 400

    url = data["url"]

    result = analyze_url(url)

    return jsonify(result)
