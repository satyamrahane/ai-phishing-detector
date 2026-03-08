from flask import Flask, jsonify
from routes import scan_route, limiter
from flask_cors import CORS
from dotenv import load_dotenv
import sys
import os

# Load .env variables
load_dotenv()

# Add parent dir to path so we can import from database/
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database.db import init_db

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-dev-key')

# Restrict CORS to allowed origins
CORS(app, origins=["http://localhost:3000", "http://127.0.0.1:5500"])

app.register_blueprint(scan_route)
limiter.init_app(app)

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"error": "Rate limit exceeded. Try again later."}), 429

if __name__ == "__main__":
    init_db()
    app.run(host='127.0.0.1', port=5000, debug=True)
