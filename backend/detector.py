from config import Config
from urllib.parse import urlparse
import whois
import datetime

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
    # Count the number of dots in the URL to detect many subdomains
    if url.count('.') > 3:
        score += 20
        reasons.append("Multiple suspicious subdomains detected")

    # Rule 5: Domain age check
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path  # fallback for bare domains
        # Strip port if present
        domain = domain.split(":")[0]

        w = whois.whois(domain)
        creation_date = w.creation_date

        # python-whois may return a list; take the earliest date
        if isinstance(creation_date, list):
            creation_date = min(creation_date)

        if creation_date:
            if isinstance(creation_date, datetime.datetime):
                age_days = (datetime.datetime.now() - creation_date).days
            else:
                # Handle date objects (not datetime)
                age_days = (datetime.date.today() - creation_date).days

            if age_days < 30:
                score += 30
                reasons.append("Domain is recently registered (possible phishing)")
    except Exception:
        # Gracefully skip domain age check if WHOIS lookup fails
        pass

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
