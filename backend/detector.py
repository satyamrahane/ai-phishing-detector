"""
detector.py — Phishing URL Analysis Engine
==========================================

Architecture:
  1. extract_features(url)  →  Build numeric feature vector from the URL.
  2. ml_predict(features)   →  Run the trained ML model (if model.pkl exists).
  3. rule_based_analyze(url)→  Fallback heuristic scoring when no model is found.
  4. analyze_url(url)       →  Public entry point: auto-chooses ML or rule-based.

To plug in a trained model, the ML teammate only needs to:
  - Train a model that accepts the feature vector from extract_features()
  - Save it with: pickle.dump(model, open("ml_model/model.pkl", "wb"))
  - The backend will automatically detect and switch to ML inference.
"""

from config import Config
from urllib.parse import urlparse
import whois
import datetime
import pickle
import os
import sys
import concurrent.futures
import requests
import socket
import base64

# Make utils/ importable when running from backend/ directory
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "utils"))

from explainability import (
    explain_suspicious_keyword,
    explain_missing_https,
    explain_url_length,
    explain_multiple_subdomains,
    explain_recent_domain,
    explain_ml_prediction,
    explain_ml_high_risk,
)

# ──────────────────────────────────────────────────────────────────────────────
# MODEL LOADER
# Attempts to load model.pkl once at startup. Returns None if not found.
# ──────────────────────────────────────────────────────────────────────────────
def _load_model():
    """Load the trained ML model from disk, or return None if unavailable."""
    if os.path.exists(Config.MODEL_PATH):
        try:
            with open(Config.MODEL_PATH, "rb") as f:
                model = pickle.load(f)
            print(f"[detector] OK: ML model loaded from: {Config.MODEL_PATH}")
            return model
        except Exception as e:
            print(f"[detector] WARNING: Failed to load model ({e}). Using rule-based fallback.")
            return None
    else:
        print(f"[detector] INFO: No model.pkl found at: {Config.MODEL_PATH}. Using rule-based detection.")
        return None

# Load once at import time — avoids reloading on every request
_ML_MODEL = _load_model()



def _do_whois_lookup(domain):
    w = whois.whois(domain)
    creation_date = w.creation_date
    if isinstance(creation_date, list):
        creation_date = min(creation_date)
    if creation_date:
        if isinstance(creation_date, datetime.datetime):
            return (datetime.datetime.now() - creation_date).days
        else:
            return (datetime.date.today() - creation_date).days
    return -1

def _safe_domain_age_days(url: str) -> int:
    try:
        parsed = urlparse(url)
        domain = (parsed.netloc or parsed.path).split(":")[0]
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_do_whois_lookup, domain)
            return future.result(timeout=5)
    except Exception:
        return -1


# ──────────────────────────────────────────────────────────────────────────────
# FEATURE EXTRACTOR
# Converts a raw URL string into a numeric list that any sklearn model can use.
# ML teammate: do NOT change feature order — retrain if new features are added.
# ──────────────────────────────────────────────────────────────────────────────
def extract_features(url: str) -> list:
    """
    Returns a fixed-length numeric feature vector for the given URL.

    Feature index reference (for the ML teammate):
      [0] has_suspicious_keyword  — 1 if any Config.SUSPICIOUS_KEYWORDS found
      [1] uses_https              — 1 if URL starts with https, 0 otherwise
      [2] url_length              — total character count of the URL
      [3] subdomain_count         — number of dots in the URL
      [4] domain_age_days         — age of domain in days (-1 if lookup fails)
    """
    url_lower = url.lower()

    # Feature 0: Suspicious keyword presence
    has_suspicious_keyword = int(
        any(kw in url_lower for kw in Config.SUSPICIOUS_KEYWORDS)
    )

    # Feature 1: HTTPS usage
    uses_https = int(url_lower.startswith("https"))

    # Feature 2: URL length
    url_length = len(url)

    # Feature 3: Subdomain / dot count
    subdomain_count = url.count(".")

    # Feature 4: Domain age in days (-1 signals lookup failure)
    domain_age_days = _safe_domain_age_days(url)

    return [
        has_suspicious_keyword,
        uses_https,
        url_length,
        subdomain_count,
        domain_age_days,
    ]


# ──────────────────────────────────────────────────────────────────────────────
# ML PREDICTION PATH
# Called only when model.pkl is present.
# Expected contract: model.predict_proba([[...features...]]) → [[p_safe, p_phish]]
# ──────────────────────────────────────────────────────────────────────────────
def ml_predict(url: str) -> int:
    """
    Use the trained ML model to produce a risk score.
    Returns:
        int (0-100)
    """
    if _ML_MODEL is None:
        return 50  # fallback if no model
        
    features = extract_features(url)

    # predict_proba returns [[prob_class_0, prob_class_1]]
    # Class 1 is assumed to be "phishing" (label=1 during training)
    proba = _ML_MODEL.predict_proba([features])[0]
    phishing_probability = proba[1]
    return int(phishing_probability * 100)


# ──────────────────────────────────────────────────────────────────────────────
# RULE-BASED FALLBACK PATH
# Active when no model.pkl is found. All existing rules are preserved exactly.
# ──────────────────────────────────────────────────────────────────────────────
def _rule_based_analyze(url: str) -> dict:
    """Heuristic scoring using hand-crafted rules. Used as ML fallback."""
    reasons = []
    score = 0
    url_lower = url.lower()

    # Rule 1: Suspicious keywords
    matched_kws = [kw for kw in Config.SUSPICIOUS_KEYWORDS if kw in url_lower]
    if matched_kws:
        score += 40
        reasons.append(explain_suspicious_keyword(matched_kws))

    # Rule 2: HTTPS check
    if not url_lower.startswith("https"):
        score += 30
        reasons.append(explain_missing_https())

    # Rule 3: URL length
    if len(url) > 75:
        score += 20
        reasons.append(explain_url_length(len(url)))

    # Rule 4: Subdomain count
    dot_count = url.count(".")
    if dot_count > 3:
        score += 20
        reasons.append(explain_multiple_subdomains(dot_count))

    # Rule 5: Domain age check
    age_days = _safe_domain_age_days(url)
    if age_days != -1 and age_days < 30:
        score += 30
        reasons.append(explain_recent_domain(age_days))

    return score, reasons

# ──────────────────────────────────────────────────────────────────────────────
# VIRUSTOTAL API INTEGRATION
# ──────────────────────────────────────────────────────────────────────────────
def check_virustotal(url: str) -> int:
    """Returns the number of engines that flagged the URL as malicious."""
    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key or api_key == "your-virustotal-api-key-here":
        return 0
        
    try:
        # VirusTotal v3 requires base64url encoded strings without padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": api_key}
        resp = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=4)
        
        if resp.status_code == 200:
            stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return stats.get("malicious", 0)
    except Exception:
        pass
        
    return 0


def get_ip_location(url: str) -> dict:
    """Resolves URL domain to IP and fetches geographic location."""
    try:
        parsed = urlparse(url)
        domain = (parsed.netloc or parsed.path).split(":")[0]
        if not domain:
            return {"ip": "0.0.0.0", "city": "Unknown", "country": "Unknown", "lat": 0, "lon": 0, "isp": "Unknown"}

        ip = socket.gethostbyname(domain)
        # Use ip-api.com (free, no key for low volume)
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "ip": ip,
                    "city": data.get("city"),
                    "country": data.get("country"),
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                    "isp": data.get("isp")
                }
        return {"ip": ip, "city": "Unknown", "country": "Unknown", "lat": 0, "lon": 0, "isp": "Unknown"}
    except Exception:
        return {"ip": "0.0.0.0", "city": "Unknown", "country": "Unknown", "lat": 0, "lon": 0, "isp": "Unknown"}


# ──────────────────────────────────────────────────────────────────────────────
# PUBLIC ENTRY POINT
# Routes to ML or rule-based depending on model availability.
# ──────────────────────────────────────────────────────────────────────────────
def analyze_url(url: str) -> dict:
    """
    Analyse a URL for phishing risk.
    Blends ML score (60%) with rule-based score (40%) if model is present.
    """
    
    # 1. Get rule-based score & reasons
    rule_score, reasons = _rule_based_analyze(url)
    
    # 2. Get ML score
    if _ML_MODEL is not None:
        ml_score = ml_predict(url)
        final_score = int(0.6 * ml_score + 0.4 * rule_score)
        reasons.append(explain_ml_prediction())
        if ml_score >= 70:
             reasons.append(explain_ml_high_risk(ml_score/100.0))
    else:
        final_score = rule_score
        
    # VirusTotal enhancement step
    malicious_count = check_virustotal(url)
    if malicious_count > 3:
        final_score += 20
        reasons.append(f"Flagged by VirusTotal ({malicious_count} engines)")
        
    final_score = min(final_score, 100)
    
    # 3. Derive status
    if final_score <= 40:
        status = "Safe"
    elif final_score <= 70:
        status = "Suspicious"
    else:
        status = "Phishing"

    # 4. Get Geolocation
    geo_data = get_ip_location(url)

    return {
        "risk_score": final_score,
        "status": status,
        "reasons": reasons,
        "ip_info": geo_data
    }
