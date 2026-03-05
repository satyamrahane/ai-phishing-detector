def analyze_url(url):

    reasons = []
    score = 0

    if "login" in url or "verify" in url:
        score += 40
        reasons.append("Suspicious keyword detected")

    if not url.startswith("https"):
        score += 30
        reasons.append("URL does not use HTTPS")

    if len(url) > 75:
        score += 20
        reasons.append("URL length unusually long")

    if score < 40:
        status = "Safe"
    elif score < 70:
        status = "Suspicious"
    else:
        status = "Phishing"

    return {
        "risk_score": score,
        "status": status,
        "reasons": reasons
    }
