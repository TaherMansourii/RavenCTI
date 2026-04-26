"""
routes/auth.py — API key + JWT middleware.

Supports two auth methods:
  1. X-Api-Key header (for programmatic / external access)
  2. Bearer token in Authorization header (for dashboard UI)

If AUTH_ENABLED=0, all requests pass through (dev mode).
"""
import hmac
import logging
from functools import wraps

from flask import request, jsonify

from ravencti.config import API_KEY, AUTH_ENABLED

log = logging.getLogger("ravencti.auth")


def require_key(f):
    """Decorator: validate X-Api-Key header or JWT Bearer token."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not AUTH_ENABLED:
            return f(*args, **kwargs)

        api_key = request.headers.get("X-Api-Key", "")
        if API_KEY and hmac.compare_digest(api_key.encode(), API_KEY.encode()):
            return f(*args, **kwargs)

        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            from ravencti.services.auth_service import decode_token
            payload = decode_token(auth_header[7:])
            if payload:
                from ravencti.db.connection import get_db
                with get_db() as conn:
                    user = conn.execute(
                        "SELECT active FROM users WHERE id=?",
                        (payload["sub"],),
                    ).fetchone()
                if user and user["active"]:
                    request.current_user = payload
                    return f(*args, **kwargs)

        log.warning("[AUTH] Rejected request from %s", request.remote_addr)
        return jsonify({"error": "Unauthorized"}), 401
    return decorated


def require_admin(f):
    """Decorator: require admin role (JWT only)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not AUTH_ENABLED:
            return f(*args, **kwargs)
        user = getattr(request, "current_user", None)
        if not user or user.get("role") != "admin":
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated
