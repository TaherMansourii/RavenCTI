"""
routes/auth_ui.py — Login, register, token refresh, user management endpoints.
"""
import logging

from flask import Blueprint, jsonify, request

from ravencti.config import AUTH_ENABLED
from ravencti.db.connection import get_db
from ravencti.services.auth_service import (
    create_token,
    decode_token,
    hash_password,
    verify_password,
)

log = logging.getLogger("ravencti.auth")
bp = Blueprint("auth_ui", __name__)


def _get_current_user():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header[7:]
    payload = decode_token(token)
    if not payload:
        return None
    with get_db() as conn:
        user = conn.execute(
            "SELECT id,username,display_name,role,active,last_login,created_at "
            "FROM users WHERE id=? AND active=1",
            (payload["sub"],),
        ).fetchone()
    return dict(user) if user else None


@bp.route("/api/auth/login", methods=["POST"])
def login():
    if not AUTH_ENABLED:
        return jsonify({
            "token": create_token(0, "admin", "admin"),
            "user": {"id": 0, "username": "admin", "role": "admin", "display_name": "Admin"},
        })

    data = request.json or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    with get_db() as conn:
        user = conn.execute(
            "SELECT id,username,password_hash,display_name,role,active "
            "FROM users WHERE username=?",
            (username,),
        ).fetchone()

    if not user or not verify_password(password, user["password_hash"]):
        return jsonify({"error": "Invalid credentials"}), 401

    if not user["active"]:
        return jsonify({"error": "Account disabled"}), 403

    token = create_token(user["id"], user["username"], user["role"])

    with get_db() as conn:
        from ravencti.utils.helpers import now_str
        conn.execute(
            "UPDATE users SET last_login=? WHERE id=?",
            (now_str(), user["id"]),
        )

    log.info("[AUTH] User '%s' logged in (role=%s)", username, user["role"])
    return jsonify({
        "token": token,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "display_name": user["display_name"],
            "role": user["role"],
        },
    })


@bp.route("/api/auth/register", methods=["POST"])
def register():
    if not AUTH_ENABLED:
        return jsonify({"error": "Auth disabled"}), 400

    user = _get_current_user()
    if not user or user["role"] != "admin":
        return jsonify({"error": "Admin access required"}), 403

    data = request.json or {}
    username = (data.get("username") or "").strip().lower()
    password = data.get("password") or ""
    role = data.get("role", "analyst")
    display_name = data.get("display_name", username)

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    if len(username) < 3:
        return jsonify({"error": "Username must be at least 3 characters"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    if role not in ("admin", "analyst"):
        role = "analyst"

    with get_db() as conn:
        existing = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        if existing:
            return jsonify({"error": "Username already exists"}), 409
        pw_hash = hash_password(password)
        conn.execute(
            "INSERT INTO users(username,password_hash,display_name,role) VALUES(?,?,?,?)",
            (username, pw_hash, display_name, role),
        )

    log.info("[AUTH] New user '%s' created (role=%s)", username, role)
    return jsonify({"success": True, "username": username, "role": role})


@bp.route("/api/auth/me")
def me():
    user = _get_current_user()
    if not user and AUTH_ENABLED:
        return jsonify({"error": "Not authenticated"}), 401
    if not AUTH_ENABLED:
        return jsonify({
            "id": 0,
            "username": "admin",
            "display_name": "Admin",
            "role": "admin",
            "auth_enabled": False,
        })
    return jsonify({**user, "auth_enabled": True})


@bp.route("/api/auth/check")
def check_auth():
    return jsonify({"auth_enabled": AUTH_ENABLED})


@bp.route("/api/auth/users")
def list_users():
    user = _get_current_user()
    if not user and AUTH_ENABLED:
        return jsonify({"error": "Not authenticated"}), 401
    if AUTH_ENABLED and user["role"] != "admin":
        return jsonify({"error": "Admin access required"}), 403

    with get_db() as conn:
        rows = conn.execute(
            "SELECT id,username,display_name,role,active,last_login,created_at "
            "FROM users ORDER BY id"
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@bp.route("/api/auth/users/<int:uid>", methods=["PATCH"])
def update_user(uid: int):
    user = _get_current_user()
    if not user and AUTH_ENABLED:
        return jsonify({"error": "Not authenticated"}), 401
    if AUTH_ENABLED and user["role"] != "admin":
        return jsonify({"error": "Admin access required"}), 403

    data = request.json or {}
    sets = []
    params = []
    for field in ("display_name", "role", "active"):
        if field in data:
            sets.append(f"{field}=?")
            params.append(data[field])

    if "password" in data and data["password"]:
        sets.append("password_hash=?")
        params.append(hash_password(data["password"]))

    if not sets:
        return jsonify({"error": "No fields to update"}), 400

    params.append(uid)
    with get_db() as conn:
        conn.execute(f"UPDATE users SET {','.join(sets)} WHERE id=?", params)

    return jsonify({"success": True})


@bp.route("/api/auth/users/<int:uid>", methods=["DELETE"])
def delete_user(uid: int):
    user = _get_current_user()
    if not user and AUTH_ENABLED:
        return jsonify({"error": "Not authenticated"}), 401
    if AUTH_ENABLED and user["role"] != "admin":
        return jsonify({"error": "Admin access required"}), 403
    if user["id"] == uid:
        return jsonify({"error": "Cannot delete yourself"}), 400

    with get_db() as conn:
        conn.execute("DELETE FROM users WHERE id=?", (uid,))
    return jsonify({"success": True})
