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
            print(f"[detector] ✅ ML model loaded from: {Config.MODEL_PATH}")
            return model
        except Exception as e:
            print(f"[detector] ⚠️  Failed to load model ({e}). Using rule-based fallback.")
            return None
    else:
        print(f"[detector] ℹ️  No model.pkl found at: {Config.MODEL_PATH}. Using rule-based detection.")
        return None

# Load once at import time — avoids reloading on every request
_ML_MODEL = _load_model()


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
    domain_age_days = -1
    try:
        parsed = urlparse(url)
        domain = (parsed.netloc or parsed.path).split(":")[0]
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = min(creation_date)
        if creation_date:
            if isinstance(creation_date, datetime.datetime):
                domain_age_days = (datetime.datetime.now() - creation_date).days
            else:
                domain_age_days = (datetime.date.today() - creation_date).days
    except Exception:
        pass  # Keep default -1

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
def _ml_predict(url: str) -> dict:
    """
    Use the trained ML model to produce a risk score and status.

    The model must expose a predict_proba() method (standard sklearn API).
    risk_score = round(phishing_probability * 100)
    """
    features = extract_features(url)

    # predict_proba returns [[prob_class_0, prob_class_1]]
    # Class 1 is assumed to be "phishing" (label=1 during training)
    proba = _ML_MODEL.predict_proba([features])[0]
    phishing_probability = proba[1]
    risk_score = min(round(phishing_probability * 100), 100)

    # Derive status from score bands (same thresholds as rule-based)
    if risk_score <= 40:
        status = "Safe"
    elif risk_score <= 70:
        status = "Suspicious"
    else:
        status = "Phishing"

    reasons = ["ML model prediction used"]
    if phishing_probability >= 0.7:
        reasons.append("High phishing probability detected by ML model")

    return {
        "risk_score": risk_score,
        "status": status,
        "reasons": reasons,
    }


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
    if any(kw in url_lower for kw in Config.SUSPICIOUS_KEYWORDS):
        score += 40
        reasons.append("Suspicious keyword detected")

    # Rule 2: HTTPS check
    if not url_lower.startswith("https"):
        score += 30
        reasons.append("URL does not use HTTPS")

    # Rule 3: URL length
    if len(url) > 75:
        score += 20
        reasons.append("URL length unusually long")

    # Rule 4: Subdomain count
    if url.count(".") > 3:
        score += 20
        reasons.append("Multiple suspicious subdomains detected")

    # Rule 5: Domain age check
    try:
        parsed = urlparse(url)
        domain = (parsed.netloc or parsed.path).split(":")[0]
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = min(creation_date)
        if creation_date:
            if isinstance(creation_date, datetime.datetime):
                age_days = (datetime.datetime.now() - creation_date).days
            else:
                age_days = (datetime.date.today() - creation_date).days
            if age_days < 30:
                score += 30
                reasons.append("Domain is recently registered (possible phishing)")
    except Exception:
        pass

    score = min(score, 100)

    if score <= 40:
        status = "Safe"
    elif score <= 70:
        status = "Suspicious"
    else:
        status = "Phishing"

    return {
        "risk_score": score,
        "status": status,
        "reasons": reasons,
    }


# ──────────────────────────────────────────────────────────────────────────────
# PUBLIC ENTRY POINT
# Routes to ML or rule-based depending on model availability.
# ──────────────────────────────────────────────────────────────────────────────
def analyze_url(url: str) -> dict:
    """
    Analyse a URL for phishing risk.

    Returns:
        {
            "risk_score": int (0-100),
            "status":     str ("Safe" | "Suspicious" | "Phishing"),
            "reasons":    list[str]
        }
    """
    if _ML_MODEL is not None:
        return _ml_predict(url)
    return _rule_based_analyze(url)
