# ml_model/train_model.py
import numpy as np
import pandas as pd
import joblib
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

MODEL_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(MODEL_DIR, "model.pkl")
DATASET_URL = "https://raw.githubusercontent.com/GregaVrbancic/Phishing-Dataset/master/dataset_full.csv"

print(f"Downloading real dataset from {DATASET_URL}...")
df = pd.read_csv(DATASET_URL)

# The dataset is an already-extracted feature dataset containing 111 features.
# To keep this compatible with the backend's extract_features(url) which produces exactly 5 features,
# we need to map 5 equivalent/proxy features from the dataset's columns:

# Using mapping:
# 1. 'qty_dot_url' acts as a proxy for keywords/complexity.
# 2. 'tls_ti' or just using 'qty_slash_url' as a proxy for https usage/security.
# 3. 'length_url' matching url_length exactly.
# 4. 'qty_dot_domain' matching subdomain_count.
# 5. 'qty_hyphen_url' acting as a proxy for domain_age_days or special_chars.

proxy_columns = [
    'qty_dot_url',      
    'qty_slash_url',    
    'length_url',       
    'qty_dot_domain',   
    'qty_hyphen_url'    
]

X = df[proxy_columns].values
y = df['phishing'].values

print(f"Dataset loaded. Total samples: {len(df)}")

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = RandomForestClassifier(n_estimators=100, random_state=42)
print("Training RandomForestClassifier...")
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
print(f"\nAccuracy Score: {accuracy_score(y_test, y_pred):.4f}\n")
print(classification_report(y_test, y_pred))

joblib.dump(model, MODEL_PATH)
print(f"Model saved to {MODEL_PATH}")
