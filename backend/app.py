from flask import Flask, request, jsonify
from urllib.parse import urlparse
from flask_cors import CORS

app = Flask(__name__)
# Enable CORS for the frontend to be able to make requests to this backend later
CORS(app)

def analyze_url(url):
    """
    Analyzes a URL for phishing indicators based on predefined rules.
    This logic can easily be expanded to integrate an ML model later.
    """
    reasons = []
    risk_score = 0
    status = "Safe"
    
    url_lower = url.lower()
    
    # Rule 1: Suspicious keywords
    suspicious_keywords = ["login", "verify", "update", "secure"]
    
    # Check if any of the keywords are in the URL string
    found_keywords = [kw for kw in suspicious_keywords if kw in url_lower]
    
    if found_keywords:
        reasons.append(f"Suspicious keyword detected: {', '.join(found_keywords)}")
        risk_score += 50
        status = "Phishing"
        
    # Rule 2: Check for HTTPS
    parsed_url = urlparse(url)
    
    # If a protocol isn't provided or parsed properly, checking scheme
    if parsed_url.scheme != 'https':
        reasons.append("URL does not use HTTPS")
        risk_score += 20
        # If it hasn't been escalated to phishing already
        if status == "Safe":
            status = "Suspicious"
            
    # Rule 3: Unusually long URL (> 75 chars)
    if len(url) > 75:
        reasons.append("URL length unusually long")
        risk_score += 15
        if status == "Safe":
            status = "Suspicious"
            
    # Normalize the risk score to a max of 100
    risk_score = min(risk_score, 100)
    
    # Optional logic fix: if safe, force score to 0
    if status == "Safe":
        risk_score = 0
        
    return {
        "risk_score": risk_score,
        "status": status,
        "reasons": reasons
    }

@app.route('/scan', methods=['POST'])
def scan_endpoint():
    data = request.get_json()
    
    # Check if data exists and 'url' is provided
    if not data or 'url' not in data:
        return jsonify({"error": "Missing 'url' field in JSON payload"}), 400
        
    url = data['url']
    
    result = analyze_url(url)
    
    # Return 200 OK with the analysis result
    return jsonify(result), 200

if __name__ == '__main__':
    # Start the backend server on port 5000
    app.run(host='127.0.0.1', port=5000, debug=True)
