"""Single-user authentication for LAN mode (PRD A7 / F12).

Loopback stays passwordless for the simplest single-machine setup. The moment
the server is bound to anything else, every route - UI, API, reports and the
WebSocket - requires a valid session.

Passwords are never stored. We keep an Argon2id hash where argon2-cffi is
installed, and fall back to scrypt from the standard library otherwise, so the
app still runs on a machine without the optional dependency.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import time
from datetime import datetime, timedelta, timezone

from . import config, db

try:  # preferred
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHash
    _PH = PasswordHasher()
    HASHER = "argon2id"
except Exception:  # pragma: no cover - optional dependency
    _PH = None
    HASHER = "scrypt"

MIN_PASSWORD_LEN = 10
COOKIE_NAME = "reconscan_session"
_ATTEMPTS: dict[str, list[float]] = {}
LOCKOUT_ATTEMPTS = 5
LOCKOUT_WINDOW = 300  # seconds


# --- hashing ----------------------------------------------------------------
def hash_password(password: str) -> str:
    if _PH is not None:
        return _PH.hash(password)
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 15, r=8, p=1, dklen=32)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(dk).decode()


def verify_password(password: str, stored: str) -> bool:
    if stored.startswith("scrypt$"):
        try:
            _, b64salt, b64dk = stored.split("$")
            salt = base64.b64decode(b64salt)
            expected = base64.b64decode(b64dk)
        except (ValueError, TypeError):
            return False
        dk = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 15, r=8, p=1, dklen=32)
        return hmac.compare_digest(dk, expected)
    if _PH is None:
        return False
    try:
        return _PH.verify(stored, password)
    except (VerifyMismatchError, VerificationError, InvalidHash):
        return False


# --- users ------------------------------------------------------------------
def user_exists() -> bool:
    with db.connect() as conn:
        return conn.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None


def get_user() -> dict | None:
    with db.connect() as conn:
        return db.row_to_dict(conn.execute("SELECT * FROM users LIMIT 1").fetchone())


def password_problem(password: str) -> str | None:
    """Return a plain-English reason the password is unacceptable, or None."""
    if len(password or "") < MIN_PASSWORD_LEN:
        return (f"Use at least {MIN_PASSWORD_LEN} characters. This password protects a machine "
                f"that can run network scanners as root, so it is worth a real passphrase - "
                f"three or four unrelated words beats a short complicated one.")
    if password.lower() in ("password12", "reconscan1", "1234567890", "qwertyuiop"):
        return "That is one of the first passwords anyone would guess. Pick something else."
    return None


def create_user(username: str, password: str) -> dict:
    username = (username or "").strip()
    if not username or len(username) > 64 or not username.replace("_", "").replace("-", "").replace(".", "").isalnum():
        raise ValueError("Username must be 1-64 characters: letters, digits, dot, dash or underscore.")
    problem = password_problem(password)
    if problem:
        raise ValueError(problem)
    if user_exists():
        raise ValueError("An account already exists. ReconScan is single-user by design.")
    uid = db.new_id()
    with db.connect() as conn:
        conn.execute("INSERT INTO users (id, username, password_hash, created_at) VALUES (?,?,?,?)",
                     (uid, username, hash_password(password), db.now()))
    db.audit("account_created", user_id=uid)
    return {"id": uid, "username": username}


def change_password(old: str, new: str) -> None:
    user = get_user()
    if not user or not verify_password(old, user["password_hash"]):
        raise ValueError("Current password is not correct.")
    problem = password_problem(new)
    if problem:
        raise ValueError(problem)
    with db.connect() as conn:
        conn.execute("UPDATE users SET password_hash=? WHERE id=?",
                     (hash_password(new), user["id"]))
        conn.execute("UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL",
                     (db.now(), user["id"]))
    db.audit("password_changed", user_id=user["id"])


# --- rate limiting ----------------------------------------------------------
def _prune(key: str) -> list[float]:
    now = time.time()
    kept = [t for t in _ATTEMPTS.get(key, []) if now - t < LOCKOUT_WINDOW]
    _ATTEMPTS[key] = kept
    return kept


def lockout_seconds(key: str) -> int:
    kept = _prune(key)
    if len(kept) < LOCKOUT_ATTEMPTS:
        return 0
    return int(LOCKOUT_WINDOW - (time.time() - kept[0])) + 1


def record_failure(key: str) -> None:
    _prune(key)
    _ATTEMPTS.setdefault(key, []).append(time.time())


def clear_failures(key: str) -> None:
    _ATTEMPTS.pop(key, None)


# --- sessions ---------------------------------------------------------------
def login(username: str, password: str, client_key: str) -> str:
    wait = lockout_seconds(client_key)
    if wait:
        raise PermissionError(
            f"Too many failed attempts. Try again in {wait} seconds. "
            f"(This limit exists so nobody can sit on your LAN guessing passwords.)")
    user = get_user()
    if not user or user["username"] != (username or "").strip() or \
            not verify_password(password or "", user["password_hash"]):
        record_failure(client_key)
        left = max(0, LOCKOUT_ATTEMPTS - len(_prune(client_key)))
        raise PermissionError(
            "That username and password do not match the account on this server."
            + (f" {left} attempt(s) left before a short lockout." if left else ""))

    clear_failures(client_key)
    token = secrets.token_urlsafe(32)
    sid = hashlib.sha256(token.encode()).hexdigest()
    expires = (datetime.now(timezone.utc) + timedelta(hours=config.SESSION_TTL_HOURS)).isoformat()
    with db.connect() as conn:
        conn.execute("INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES (?,?,?,?)",
                     (sid, user["id"], db.now(), expires))
        conn.execute("UPDATE users SET last_login_at=? WHERE id=?", (db.now(), user["id"]))
    db.audit("login", user_id=user["id"])
    return token


def session_user(token: str | None) -> dict | None:
    if not token:
        return None
    sid = hashlib.sha256(token.encode()).hexdigest()
    with db.connect() as conn:
        row = conn.execute(
            "SELECT s.expires_at, s.revoked_at, u.id, u.username FROM sessions s "
            "JOIN users u ON u.id = s.user_id WHERE s.id = ?", (sid,)).fetchone()
    if not row:
        return None
    if row["revoked_at"]:
        return None
    try:
        if datetime.fromisoformat(row["expires_at"]) < datetime.now(timezone.utc):
            return None
    except ValueError:
        return None
    return {"id": row["id"], "username": row["username"]}


def logout(token: str | None) -> None:
    if not token:
        return
    sid = hashlib.sha256(token.encode()).hexdigest()
    with db.connect() as conn:
        conn.execute("UPDATE sessions SET revoked_at=? WHERE id=? AND revoked_at IS NULL",
                     (db.now(), sid))
    db.audit("logout")


def revoke_all() -> int:
    with db.connect() as conn:
        cur = conn.execute("UPDATE sessions SET revoked_at=? WHERE revoked_at IS NULL",
                           (db.now(),))
        return cur.rowcount


def purge_expired() -> None:
    with db.connect() as conn:
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (db.now(),))
