from config import Config
from urllib.parse import urlparse

def analyze_url(url):
    reasons = []
    score = 0
    url_lower = url.lower()

    # Rule 1: Suspicious keywords
    if any(keyword in url_lower for keyword in Config.SUSPICIOUS_KEYWORDS):
        score += 40
        reasons.append("Suspicious keyword detected")

    # Rule 2: Check for HTTPS
    if not url_lower.startswith("https"):
        score += 30
        reasons.append("URL does not use HTTPS")

    # Rule 3: URL length
    if len(url) > 75:
        score += 20
        reasons.append("URL length unusually long")

    # Rule 4: Subdomains count
    # Count dots to estimate subdomains
    parsed = urlparse(url)
    domain = parsed.netloc if parsed.netloc else parsed.path.split('/')[0]
    # A standard bare domain has 1 dot (e.g., example.com)
    # If the count is > 3, we increase the risk.
    if domain.count('.') > 3:
        score += 20
        reasons.append("Too many subdomains detected")

    # Limit risk score to 100 maximum
    score = min(score, 100)

    # Calculate status based on ranges
    if score <= 40:
        status = "Safe"
    elif score <= 70:
        status = "Suspicious"
    else:
        status = "Phishing"

    return {
        "risk_score": score,
        "status": status,
        "reasons": reasons
    }
