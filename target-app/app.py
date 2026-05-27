"""
Target application — Flask app with endpoints designed to produce
realistic CRS false positives when serving legitimate traffic.
"""
import json
import os
from flask import Flask, request, jsonify

app = Flask(__name__)

USERS = [
    {"id": 1, "name": "Alice Johnson", "role": "admin"},
    {"id": 2, "name": "Bob Smith", "role": "user"},
    {"id": 3, "name": "Carol White", "role": "editor"},
]

PRODUCTS = [
    "Running shoes", "Drop-down keyboard tray", "Union Jack mug",
    "Select all-purpose cleaner", "Update cable adapter", "Insert desk lamp",
]


@app.route("/")
def homepage():
    return """
    <html><body>
    <h1>WAF Tuner Demo App</h1>
    <ul>
      <li><a href="/search?q=select all products">Search</a></li>
      <li><a href="/api/users">Users API</a></li>
    </ul>
    </body></html>
    """


@app.route("/search")
def search():
    """
    Search endpoint. Legitimate queries like 'select all items' or
    'drop down menu' trigger CRS SQLi/command injection false positives.
    """
    q = request.args.get("q", "")
    results = [p for p in PRODUCTS if q.lower() in p.lower()] if q else PRODUCTS
    return jsonify({"query": q, "results": results, "count": len(results)})


@app.route("/login", methods=["POST"])
def login():
    """
    Login endpoint. Passwords with special chars like P@ssw0rd!#$
    trigger CRS false positives on SQL/XSS rules.
    """
    data = request.form or request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    if username and password:
        return jsonify({"status": "ok", "user": username, "token": "demo-token-abc123"})
    return jsonify({"status": "error", "message": "Missing credentials"}), 400


@app.route("/comment", methods=["POST"])
def comment():
    """
    Comment endpoint. Rich text / markdown content triggers CRS XSS rules.
    e.g. <em>italic</em>, <script> tags in markdown previews.
    """
    data = request.form or request.get_json(silent=True) or {}
    body = data.get("body", "")
    author = data.get("author", "anonymous")
    return jsonify({
        "status": "ok",
        "comment": {"author": author, "body": body, "id": 42}
    })


@app.route("/upload", methods=["POST"])
def upload():
    """
    File upload endpoint. Binary content triggers CRS false positives.
    """
    files = request.files
    filename = None
    if "file" in files:
        filename = files["file"].filename
    return jsonify({"status": "ok", "filename": filename})


@app.route("/api/users")
def api_users():
    """JSON API for users list."""
    return jsonify({"users": USERS, "total": len(USERS)})


@app.route("/api/data", methods=["POST"])
def api_data():
    """
    Generic JSON POST. Nested payloads with special chars trigger CRS rules.
    e.g. {"filter": "name LIKE '%select%'", "tags": ["<b>bold</b>"]}
    """
    data = request.get_json(silent=True) or {}
    return jsonify({"status": "ok", "received": data})


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "not found", "path": request.path}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "internal server error"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
