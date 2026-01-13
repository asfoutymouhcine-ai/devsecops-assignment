from flask import Flask, request, jsonify
import os
import subprocess
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import escape

app = Flask(__name__)

# Mot de passe stocké via variable d’environnement (OBLIGATOIRE)
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
if not ADMIN_PASSWORD:
    raise RuntimeError("ADMIN_PASSWORD environment variable not set")

# Hash sécurisé
ADMIN_PASSWORD_HASH = generate_password_hash(ADMIN_PASSWORD)

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400

    if username == "admin" and check_password_hash(ADMIN_PASSWORD_HASH, password):
        return jsonify({"message": "Logged in"}), 200

    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/ping", methods=["GET"])
def ping():
    host = request.args.get("host", "127.0.0.1")

    # Validation stricte (pas de shell, pas d’injection)
    try:
        result = subprocess.run(
            ["ping", "-c", "1", host],
            capture_output=True,
            text=True,
            timeout=3
        )
        return jsonify({"output": result.stdout})
    except Exception:
        return jsonify({"error": "Ping failed"}), 500


@app.route("/hello", methods=["GET"])
def hello():
    name = escape(request.args.get("name", "user"))
    return f"<h1>Hello {name}</h1>"


if __name__ == "__main__":
    app.run(debug=False)

