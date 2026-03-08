# ml_model/train_model.py
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import os

MODEL_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(MODEL_DIR, "model.pkl")

# Synthetic training data
np.random.seed(42)
n = 1000

# Features: [url_length, has_https, num_subdomains, has_keywords, special_chars]
X_safe = np.column_stack([
    np.random.randint(10, 60, n//2),
    np.ones(n//2),
    np.random.randint(0, 2, n//2),
    np.zeros(n//2),
    np.random.randint(0, 3, n//2)
])

X_phish = np.column_stack([
    np.random.randint(60, 200, n//2),
    np.random.randint(0, 2, n//2),
    np.random.randint(2, 6, n//2),
    np.ones(n//2),
    np.random.randint(4, 15, n//2)
])

X = np.vstack([X_safe, X_phish])
y = np.array([0] * (n//2) + [1] * (n//2))

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

print(classification_report(y_test, model.predict(X_test)))
joblib.dump(model, MODEL_PATH)
print(f"Model saved to {MODEL_PATH}")
