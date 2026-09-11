"""Sample HTTPS service used to verify tracing of unmodified applications.

Contains no instrumentation.
"""

import os
import time

from flask import Flask, jsonify

app = Flask(__name__)

USERS = [
    {"id": 1, "name": "ada"},
    {"id": 2, "name": "grace"},
    {"id": 3, "name": "katherine"},
]


@app.get("/health")
def health():
    return "ok"


@app.get("/users")
def list_users():
    return jsonify(USERS)


@app.post("/users")
def create_user():
    return jsonify({"id": len(USERS) + 1, "name": "new"}), 201


@app.get("/users/<int:user_id>")
def get_user(user_id):
    if user_id == 999:
        return jsonify({"error": "no such user"}), 404
    return jsonify(USERS[0])


@app.get("/slow")
def slow():
    time.sleep(0.15)
    return "slow"


@app.get("/error")
def error():
    return jsonify({"error": "deliberate failure"}), 500


if __name__ == "__main__":
    cert = os.environ.get("CERT", "../certs/cert.pem")
    key = os.environ.get("KEY", "../certs/key.pem")
    port = int(os.environ.get("PORT", "8444"))
    # threaded=False keeps the process single-threaded, so the request flow is
    # easy to follow when reading captured events by hand.
    app.run(host="0.0.0.0", port=port, ssl_context=(cert, key), threaded=False)
