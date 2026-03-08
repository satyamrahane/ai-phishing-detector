"""
train_model.py — ML Model Training Scaffold
============================================

Instructions for the ML teammate:
  1. Replace SAMPLE_DATA below with your real labelled dataset.
  2. Run:  python ml_model/train_model.py
  3. This saves ml_model/model.pkl — the backend picks it up automatically.

Feature vector produced by detector.extract_features(url):
  [0] has_suspicious_keyword  (0 or 1)
  [1] uses_https              (0 or 1)
  [2] url_length              (int)
  [3] subdomain_count         (int, number of dots)
  [4] domain_age_days         (int, -1 if WHOIS lookup failed)

Label convention:
  0 = Safe / Legitimate
  1 = Phishing
"""

import os
import pickle
import sys

# ── Optional: uncomment if sklearn is installed ────────────────────────────
# from sklearn.ensemble import RandomForestClassifier
# from sklearn.model_selection import train_test_split
# from sklearn.metrics import classification_report
# ──────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# SAMPLE DATA (replace with real dataset)
# Each row: [has_kw, uses_https, url_len, dot_count, domain_age_days]  label
# ─────────────────────────────────────────────────────────────────────────────
SAMPLE_DATA = [
    # features                        label
    ([1, 0, 120, 5, 5],               1),  # phishing
    ([1, 0,  95, 4, 10],              1),  # phishing
    ([0, 1,  35, 1, 500],             0),  # safe
    ([0, 1,  40, 2, 1200],            0),  # safe
    ([1, 0,  80, 3, 2],               1),  # phishing — new domain
    ([0, 1,  28, 1, 3000],            0),  # safe
]

def train_and_save():
    """Train a RandomForest classifier and save it as model.pkl."""

    # Ensure sklearn is available
    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import classification_report
    except ImportError:
        print("❌  scikit-learn is not installed.")
        print("    Run: pip install scikit-learn")
        sys.exit(1)

    # Unpack features and labels
    X = [row[0] for row in SAMPLE_DATA]
    y = [row[1] for row in SAMPLE_DATA]

    # Split — skip if dataset too small for a proper split
    if len(X) >= 10:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )
    else:
        print("⚠️  Small dataset — training on all samples (no test split).")
        X_train, y_train = X, y
        X_test, y_test = X, y

    # Train
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_test)
    print("\n📊  Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Safe", "Phishing"]))

    # Save
    model_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(model_dir, "model.pkl")
    with open(model_path, "wb") as f:
        pickle.dump(model, f)

    print(f"✅  Model saved to: {model_path}")
    print("    Restart the Flask backend for the new model to take effect.")


if __name__ == "__main__":
    train_and_save()
