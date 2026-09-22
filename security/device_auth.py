"""
security/device_auth.py
-------------------------
Device registration and authentication.

Implements Algorithm 2 (IoT Device Authentication) from Chapter Four.
Each device is issued a device_uid (public identifier) and a device_secret
(shown once at registration); only a salted hash of the secret is stored,
mirroring how user passwords are handled.
"""

import secrets

from werkzeug.security import generate_password_hash, check_password_hash

from database.db import get_db, log_event


def register_device(device_name: str, registered_by_user_id: int):
    """
    Register a new device. Returns (device_uid, device_secret) where
    device_secret is returned ONCE in plaintext for the administrator to
    copy into the physical/simulated device's configuration. It is never
    stored or logged in plaintext.
    """
    device_uid = "dev-" + secrets.token_hex(4)
    device_secret = secrets.token_urlsafe(16)
    secret_hash = generate_password_hash(device_secret, method="pbkdf2:sha256")

    conn = get_db()
    conn.execute(
        "INSERT INTO Devices (device_uid, device_secret_hash, device_name, "
        "registered_by, status) VALUES (?, ?, ?, ?, 'active')",
        (device_uid, secret_hash, device_name, registered_by_user_id),
    )
    conn.commit()
    log_event("user", registered_by_user_id, "device_registered", device_uid)
    return device_uid, device_secret


def authenticate_device(device_uid: str, device_secret: str):
    """
    Verify device credentials.
    Returns the device row on success, or None on failure.
    Every attempt is logged for security-monitoring purposes.
    """
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM Devices WHERE device_uid = ?", (device_uid,)
    ).fetchone()

    if row is None:
        log_event("device", device_uid, "device_auth_failed_unknown_device", "")
        return None

    if row["status"] != "active":
        log_event("device", device_uid, "device_auth_rejected_inactive_status",
                   f"status={row['status']}")
        return None

    if not check_password_hash(row["device_secret_hash"], device_secret):
        log_event("device", device_uid, "device_auth_failed_bad_secret", "")
        return None

    conn.execute(
        "UPDATE Devices SET last_seen = CURRENT_TIMESTAMP WHERE device_id = ?",
        (row["device_id"],),
    )
    conn.commit()
    return row


def mark_device_suspicious(device_uid: str, reason: str):
    conn = get_db()
    conn.execute(
        "UPDATE Devices SET status = 'suspicious' WHERE device_uid = ?",
        (device_uid,),
    )
    conn.commit()
    log_event("system", device_uid, "device_marked_suspicious", reason)
