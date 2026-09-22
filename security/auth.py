"""
security/auth.py
------------------
User authentication, password hashing, session management, and
Role-Based Access Control (RBAC) helpers.

Algorithm 1 (User Authentication) and the RBAC enforcement described in
Chapter Four are implemented here.
"""

import re
import time
from functools import wraps

from flask import session, request, redirect, url_for, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

from config import config
from database.db import get_db, log_event

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,50}$")


# --- Password hashing ---------------------------------------------------------

def hash_password(plain_password: str) -> str:
    """Hash a password with a salted, iterated PBKDF2 hash (never store plaintext)."""
    return generate_password_hash(plain_password, method="pbkdf2:sha256", salt_length=16)


def verify_password(plain_password: str, password_hash: str) -> bool:
    return check_password_hash(password_hash, plain_password)


# --- Input validation ----------------------------------------------------------

def is_valid_username(username: str) -> bool:
    return bool(username) and bool(USERNAME_RE.match(username))


def is_valid_password(password: str) -> bool:
    # Minimum length policy; kept simple and explicit for an undergraduate prototype.
    return bool(password) and len(password) >= 8


# --- Algorithm 1: User authentication ------------------------------------------

def authenticate_user(username: str, password: str, remote_addr: str):
    """
    Verify a username/password pair against the Users table.
    Returns the user row (sqlite3.Row) on success, or None on failure.
    Every attempt — success or failure — is written to AuditLogs.
    """
    if not is_valid_username(username):
        log_event("user", username or "unknown", "login_rejected_invalid_input",
                   f"from {remote_addr}")
        return None

    conn = get_db()
    row = conn.execute(
        "SELECT * FROM Users WHERE username = ?", (username,)
    ).fetchone()

    if row is None or not verify_password(password, row["password_hash"]):
        log_event("user", username, "login_failed", f"from {remote_addr}")
        return None

    conn.execute(
        "UPDATE Users SET last_login = CURRENT_TIMESTAMP WHERE user_id = ?",
        (row["user_id"],),
    )
    conn.commit()
    log_event("user", username, "login_success", f"from {remote_addr}")
    return row


# --- Session management ---------------------------------------------------------

def start_session(user_row):
    session.clear()
    session["user_id"] = user_row["user_id"]
    session["username"] = user_row["username"]
    session["role"] = user_row["role"]
    session["last_active"] = time.time()


def session_is_valid() -> bool:
    if "user_id" not in session:
        return False
    last_active = session.get("last_active", 0)
    if time.time() - last_active > config.SESSION_TIMEOUT_MINUTES * 60:
        session.clear()
        return False
    session["last_active"] = time.time()  # sliding expiration
    return True


def end_session():
    if "username" in session:
        log_event("user", session["username"], "logout", "")
    session.clear()


# --- RBAC decorators --------------------------------------------------------------

def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session_is_valid():
            if request.path.startswith("/api/"):
                return jsonify({"error": "authentication_required"}), 401
            return redirect(url_for("views.login_page"))
        return view_func(*args, **kwargs)
    return wrapped


def role_required(*allowed_roles):
    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            if not session_is_valid():
                if request.path.startswith("/api/"):
                    return jsonify({"error": "authentication_required"}), 401
                return redirect(url_for("views.login_page"))
            if session.get("role") not in allowed_roles:
                log_event("user", session.get("username"), "authorization_denied",
                           f"role={session.get('role')} path={request.path}")
                if request.path.startswith("/api/"):
                    return jsonify({"error": "forbidden"}), 403
                return jsonify({"error": "forbidden"}), 403
            return view_func(*args, **kwargs)
        return wrapped
    return decorator
