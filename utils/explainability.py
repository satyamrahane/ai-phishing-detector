"""
explainability.py — Human-Readable Phishing Explanation Functions
=================================================================

Each function corresponds to one phishing detection rule and returns
a clear, user-facing reason string.

Usage (in detector.py):
    from utils.explainability import (
        explain_suspicious_keyword,
        explain_missing_https,
        explain_url_length,
        explain_multiple_subdomains,
        explain_recent_domain,
        explain_ml_prediction,
        explain_ml_high_risk,
    )
"""

import sys
import os

# ──────────────────────────────────────────────────────────────────────────────
# Rule 1 — Suspicious keywords found in URL
# ──────────────────────────────────────────────────────────────────────────────
def explain_suspicious_keyword(matched_keywords: list = None) -> str:
    """
    Returns a reason message when a suspicious keyword is detected in the URL.

    Args:
        matched_keywords: optional list of matched words to include in message.

    Returns:
        Human-readable string explaining the suspicious keyword finding.

    Example:
        >>> explain_suspicious_keyword(["login", "verify"])
        'Suspicious keywords detected in URL: login, verify'
        >>> explain_suspicious_keyword()
        'Suspicious keyword detected in URL'
    """
    if matched_keywords:
        joined = ", ".join(matched_keywords)
        return f"Suspicious keywords detected in URL: {joined}"
    return "Suspicious keyword detected in URL"


# ──────────────────────────────────────────────────────────────────────────────
# Rule 2 — URL does not use HTTPS
# ──────────────────────────────────────────────────────────────────────────────
def explain_missing_https() -> str:
    """
    Returns a reason message when the URL does not use HTTPS.

    Returns:
        Human-readable string explaining the missing HTTPS finding.

    Example:
        >>> explain_missing_https()
        'URL does not use HTTPS — connection may not be secure'
    """
    return "URL does not use HTTPS — connection may not be secure"


# ──────────────────────────────────────────────────────────────────────────────
# Rule 3 — URL is excessively long
# ──────────────────────────────────────────────────────────────────────────────
def explain_url_length(url_length: int = None, threshold: int = 75) -> str:
    """
    Returns a reason message when the URL length exceeds a safe threshold.

    Args:
        url_length: actual length of the URL in characters.
        threshold:  the character limit above which URLs are considered long.

    Returns:
        Human-readable string explaining the URL length finding.

    Example:
        >>> explain_url_length(120, 75)
        'URL is excessively long (120 characters) — phishing URLs often hide behind long paths'
        >>> explain_url_length()
        'URL length is unusually long — may be attempting to obscure destination'
    """
    if url_length is not None:
        return (
            f"URL is excessively long ({url_length} characters)"
            f" — phishing URLs often hide behind long paths"
        )
    return "URL length is unusually long — may be attempting to obscure destination"


# ──────────────────────────────────────────────────────────────────────────────
# Rule 4 — Multiple suspicious subdomains
# ──────────────────────────────────────────────────────────────────────────────
def explain_multiple_subdomains(dot_count: int = None) -> str:
    """
    Returns a reason message when the URL contains an excessive number of dots,
    indicating multiple nested subdomains (common in spoofed URLs).

    Args:
        dot_count: number of dots found in the URL.

    Returns:
        Human-readable string explaining the multiple subdomains finding.

    Example:
        >>> explain_multiple_subdomains(5)
        'Multiple suspicious subdomains detected (5 dots) — common in spoofed URLs'
        >>> explain_multiple_subdomains()
        'Multiple suspicious subdomains detected — common in spoofed URLs'
    """
    if dot_count is not None:
        return (
            f"Multiple suspicious subdomains detected ({dot_count} dots)"
            f" — common in spoofed URLs"
        )
    return "Multiple suspicious subdomains detected — common in spoofed URLs"


# ──────────────────────────────────────────────────────────────────────────────
# Rule 5 — Domain was registered very recently
# ──────────────────────────────────────────────────────────────────────────────
def explain_recent_domain(age_days: int = None) -> str:
    """
    Returns a reason message when the domain was registered very recently,
    which is a strong indicator of a phishing campaign.

    Args:
        age_days: age of the domain in days since registration.

    Returns:
        Human-readable string explaining the recent domain registration finding.

    Example:
        >>> explain_recent_domain(7)
        'Domain is recently registered (7 days old) — possible phishing campaign'
        >>> explain_recent_domain()
        'Domain is recently registered (possible phishing)'
    """
    if age_days is not None:
        return (
            f"Domain is recently registered ({age_days} days old)"
            f" — possible phishing campaign"
        )
    return "Domain is recently registered (possible phishing)"


# ──────────────────────────────────────────────────────────────────────────────
# ML path — base explanation when ML model is used
# ──────────────────────────────────────────────────────────────────────────────
def explain_ml_prediction() -> str:
    """
    Returns a base reason message indicating an ML model was used for prediction.

    Returns:
        Human-readable string noting ML model was used.

    Example:
        >>> explain_ml_prediction()
        'Risk score determined by trained ML model'
    """
    return "Risk score determined by trained ML model"


# ──────────────────────────────────────────────────────────────────────────────
# ML path — high-confidence phishing signal from ML model
# ──────────────────────────────────────────────────────────────────────────────
def explain_ml_high_risk(probability: float = None) -> str:
    """
    Returns a reason message when the ML model assigns a high phishing probability.

    Args:
        probability: raw phishing probability from model.predict_proba() (0.0–1.0).

    Returns:
        Human-readable string explaining the high-risk ML finding.

    Example:
        >>> explain_ml_high_risk(0.93)
        'ML model detected high phishing probability (93%)'
        >>> explain_ml_high_risk()
        'High phishing probability detected by ML model'
    """
    if probability is not None:
        pct = round(probability * 100)
        return f"ML model detected high phishing probability ({pct}%)"
    return "High phishing probability detected by ML model"
