from flask import Flask
from routes import scan_route
from flask_cors import CORS

app = Flask(__name__)

# Enable CORS (Cross-Origin Resource Sharing) for the entire application
CORS(app)

app.register_blueprint(scan_route)

if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5000, debug=True)
