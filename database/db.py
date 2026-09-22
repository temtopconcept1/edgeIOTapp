"""
database/db.py
---------------
Lightweight SQLite access layer. Uses parameterized queries throughout to
prevent SQL injection, and a per-thread connection so it is safe to call
from the Flask request thread, the edge-gateway thread, and the IoT
simulator thread concurrently.
"""

import sqlite3
import threading
import os

from config import config

_local = threading.local()


def get_db():
    """Return a thread-local SQLite connection with row factory enabled."""
    if not hasattr(_local, "conn"):
        # timeout=10 + WAL mode reduce "database is locked" errors when the
        # request thread, the edge-gateway thread, and the IoT simulator
        # thread all write around the same time.
        _local.conn = sqlite3.connect(
            config.DATABASE_PATH, check_same_thread=False, timeout=10
        )
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA foreign_keys = ON;")
        _local.conn.execute("PRAGMA journal_mode = WAL;")
        _local.conn.execute("PRAGMA busy_timeout = 10000;")
    return _local.conn


def init_db():
    """Create tables if they do not already exist and seed a default admin."""
    os.makedirs(os.path.dirname(config.DATABASE_PATH), exist_ok=True)
    conn = get_db()
    schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
    with open(schema_path, "r") as f:
        conn.executescript(f.read())
    conn.commit()

    # Seed a default administrator account if no users exist yet.
    from security.auth import hash_password  # local import avoids circular import
    cur = conn.execute("SELECT COUNT(*) AS c FROM Users")
    if cur.fetchone()["c"] == 0:
        conn.execute(
            "INSERT INTO Users (username, password_hash, role) VALUES (?, ?, ?)",
            (
                config.DEFAULT_ADMIN_USERNAME,
                hash_password(config.DEFAULT_ADMIN_PASSWORD),
                "admin",
            ),
        )
        conn.commit()
        log_event("system", "init_db", "seed_default_admin",
                   f"Created default admin '{config.DEFAULT_ADMIN_USERNAME}'. "
                   f"Change the default password immediately.")


def log_event(actor_type, actor_id, action, details=""):
    """Write an entry to AuditLogs. Never raises — logging must not crash callers."""
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO AuditLogs (actor_type, actor_id, action, details) "
            "VALUES (?, ?, ?, ?)",
            (actor_type, str(actor_id), action, details),
        )
        conn.commit()
    except Exception as exc:  # pragma: no cover - defensive logging path
        print(f"[AuditLog error] {exc}")
