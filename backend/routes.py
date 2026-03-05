from flask import Blueprint, request, jsonify
from detector import analyze_url

scan_route = Blueprint("scan_route", __name__)

@scan_route.route("/scan", methods=["POST"])
def scan():

    data = request.json
    url = data["url"]

    result = analyze_url(url)

    return jsonify(result)
