"""
services/auth_service.py — JWT token management and password utilities.
"""
import logging
from datetime import datetime, timedelta, timezone

import jwt

from ravencti.config import JWT_SECRET, JWT_EXPIRATION_H, JWT_ALGORITHM

log = logging.getLogger("ravencti.auth")


def hash_password(password: str) -> str:
    import bcrypt
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    import bcrypt
    try:
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    except Exception:
        return False


def create_token(user_id: int, username: str, role: str) -> str:
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_H),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        log.debug("[AUTH] Token expired")
        return None
    except jwt.InvalidTokenError as e:
        log.debug("[AUTH] Invalid token: %s", e)
        return None
