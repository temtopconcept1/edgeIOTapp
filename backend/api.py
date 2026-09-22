"""
backend/api.py
----------------
JSON REST API consumed by the dashboard's JavaScript. Every endpoint is
authenticated (login_required) and management endpoints are additionally
restricted to the 'admin' role (role_required), implementing RBAC as
specified in Chapter Three, Section 3.5 / Chapter Four, Section 4.6.

All endpoints are subject to a generic per-IP API rate limit (see
before_request below) to mitigate excessive-request / DoS-like behaviour
against the backend, independent of the edge gateway's own per-device
rate limiting.
"""

from flask import Blueprint, request, jsonify, session

from database.db import get_db, log_event
from security.auth import login_required, role_required, is_valid_username, \
    is_valid_password, hash_password
from security.device_auth import register_device
from security.rate_limit import is_api_rate_limited

api = Blueprint("api", __name__, url_prefix="/api")


@api.before_request
def _enforce_api_rate_limit():
    ip = request.remote_addr or "unknown"
    if is_api_rate_limited(ip):
        return jsonify({"error": "rate_limited",
                         "message": "Too many requests. Please slow down."}), 429


@api.route("/summary")
@login_required
def summary():
    conn = get_db()
    devices = conn.execute("SELECT COUNT(*) c FROM Devices").fetchone()["c"]
    active_devices = conn.execute(
        "SELECT COUNT(*) c FROM Devices WHERE status = 'active'").fetchone()["c"]
    unresolved_alerts = conn.execute(
        "SELECT COUNT(*) c FROM Alerts WHERE resolved = 0").fetchone()["c"]
    users = conn.execute("SELECT COUNT(*) c FROM Users").fetchone()["c"]
    readings_today = conn.execute(
        "SELECT COUNT(*) c FROM SensorData WHERE date(recorded_at) = date('now')"
    ).fetchone()["c"]
    return jsonify({
        "total_devices": devices,
        "active_devices": active_devices,
        "unresolved_alerts": unresolved_alerts,
        "total_users": users,
        "readings_today": readings_today,
    })


@api.route("/devices", methods=["GET"])
@login_required
def list_devices():
    conn = get_db()
    rows = conn.execute(
        "SELECT device_id, device_uid, device_name, status, last_seen "
        "FROM Devices ORDER BY device_id DESC"
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@api.route("/devices", methods=["POST"])
@role_required("admin")
def create_device():
    data = request.get_json(silent=True) or {}
    name = (data.get("device_name") or "").strip()
    if not name or len(name) > 100:
        return jsonify({"error": "invalid_device_name"}), 400

    device_uid, device_secret = register_device(name, session["user_id"])
    # The plaintext secret is returned exactly once, in the HTTP response to
    # the authenticated administrator who just created it — never persisted.
    return jsonify({
        "device_uid": device_uid,
        "device_secret": device_secret,
        "warning": "Copy this secret now — it cannot be retrieved again."
    }), 201


@api.route("/devices/<device_uid>/status", methods=["POST"])
@role_required("admin")
def set_device_status(device_uid):
    data = request.get_json(silent=True) or {}
    new_status = data.get("status")
    if new_status not in ("active", "inactive"):
        return jsonify({"error": "invalid_status"}), 400
    conn = get_db()
    conn.execute("UPDATE Devices SET status = ? WHERE device_uid = ?",
                 (new_status, device_uid))
    conn.commit()
    log_event("user", session["username"], "device_status_changed",
              f"{device_uid} -> {new_status}")
    return jsonify({"ok": True})


@api.route("/sensor-data", methods=["GET"])
@login_required
def sensor_data():
    device_id = request.args.get("device_id", type=int)
    limit = min(request.args.get("limit", default=50, type=int), 200)
    conn = get_db()
    if device_id:
        rows = conn.execute(
            "SELECT reading_id, device_id, temperature, humidity, status, recorded_at "
            "FROM SensorData WHERE device_id = ? ORDER BY reading_id DESC LIMIT ?",
            (device_id, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT reading_id, device_id, temperature, humidity, status, recorded_at "
            "FROM SensorData ORDER BY reading_id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return jsonify([dict(r) for r in rows][::-1])


@api.route("/alerts", methods=["GET"])
@login_required
def list_alerts():
    only_unresolved = request.args.get("unresolved") == "1"
    conn = get_db()
    query = ("SELECT a.alert_id, a.device_id, d.device_name, a.alert_type, "
              "a.severity, a.message, a.resolved, a.created_at "
              "FROM Alerts a LEFT JOIN Devices d ON a.device_id = d.device_id")
    if only_unresolved:
        query += " WHERE a.resolved = 0"
    query += " ORDER BY a.alert_id DESC LIMIT 100"
    rows = conn.execute(query).fetchall()
    return jsonify([dict(r) for r in rows])


@api.route("/alerts/<int:alert_id>/resolve", methods=["POST"])
@role_required("admin")
def resolve_alert(alert_id):
    conn = get_db()
    conn.execute("UPDATE Alerts SET resolved = 1 WHERE alert_id = ?", (alert_id,))
    conn.commit()
    log_event("user", session["username"], "alert_resolved", str(alert_id))
    return jsonify({"ok": True})


@api.route("/logs", methods=["GET"])
@role_required("admin")
def audit_logs():
    conn = get_db()
    rows = conn.execute(
        "SELECT log_id, actor_type, actor_id, action, details, created_at "
        "FROM AuditLogs ORDER BY log_id DESC LIMIT 200"
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@api.route("/users", methods=["GET"])
@role_required("admin")
def list_users():
    conn = get_db()
    rows = conn.execute(
        "SELECT user_id, username, role, created_at, last_login FROM Users "
        "ORDER BY user_id"
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@api.route("/users", methods=["POST"])
@role_required("admin")
def create_user():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    role = data.get("role") or "user"

    if not is_valid_username(username):
        return jsonify({"error": "invalid_username",
                         "message": "3-50 chars: letters, numbers, . _ -"}), 400
    if not is_valid_password(password):
        return jsonify({"error": "invalid_password",
                         "message": "Minimum 8 characters."}), 400
    if role not in ("admin", "user"):
        return jsonify({"error": "invalid_role"}), 400

    conn = get_db()
    existing = conn.execute("SELECT 1 FROM Users WHERE username = ?",
                             (username,)).fetchone()
    if existing:
        return jsonify({"error": "username_taken"}), 409

    conn.execute(
        "INSERT INTO Users (username, password_hash, role) VALUES (?, ?, ?)",
        (username, hash_password(password), role),
    )
    conn.commit()
    log_event("user", session["username"], "user_created", f"{username} ({role})")
    return jsonify({"ok": True}), 201


@api.route("/me")
@login_required
def me():
    return jsonify({"username": session.get("username"), "role": session.get("role")})
