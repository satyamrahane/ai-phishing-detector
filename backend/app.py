from flask import Flask
from routes import scan_route
from flask_cors import CORS
import sys
import os

# Add parent dir to path so we can import from database/
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database.db import init_db

app = Flask(__name__)

# Enable CORS (Cross-Origin Resource Sharing) for the entire application
CORS(app)

app.register_blueprint(scan_route)

if __name__ == "__main__":
    init_db()
    app.run(host='127.0.0.1', port=5000, debug=True)
