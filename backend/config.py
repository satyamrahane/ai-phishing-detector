import os

class Config:
    DEBUG = True
    SUSPICIOUS_KEYWORDS = ["login", "verify", "update", "secure"]

    # Path to the trained ML model pickle file.
    # The ML teammate should place model.pkl here after training.
    MODEL_PATH = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "ml_model", "model.pkl"
    )
