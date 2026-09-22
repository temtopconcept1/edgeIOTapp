"""
edge/gateway.py
-----------------
The Edge Gateway is the core of the secure edge computing architecture.
For every incoming MQTT message it performs, in order:

    1. Device authentication            (security/device_auth.py)
    2. Per-device rate limiting          (security/rate_limit.py)  -> DoS mitigation
    3. Replay-attack protection          (sequence number + timestamp freshness)
    4. Data validation                   (structure + plausible physical ranges)
    5. Local processing / anomaly detection (threshold comparison)
    6. Local storage                     (SensorData table)
    7. Alert generation                  (Alerts table) when thresholds are breached
    8. Forwarding of processed data to the backend REST API over HTTP(S)
    9. Security / audit logging at every decision point

This corresponds to Algorithms 2-5 in Chapter Four.
"""

import time
import threading

from config import config
from database.db import get_db, log_event
from security.device_auth import authenticate_device, mark_device_suspicious
from security.rate_limit import is_device_rate_limited
from edge.mqtt_broker_sim import broker

TOPIC_PREFIX = "ssems/devices"          # topic pattern: ssems/devices/<device_uid>/data

# In-memory count of consecutive anomalous readings per device, used to
# avoid raising an alert on a single noisy/transient outlier.
_consecutive_anomalies = {}


def _validate_payload(payload: dict):
    """
    Structural + range validation of an incoming sensor message.
    Returns (is_valid: bool, reason: str).
    """
    required_fields = {"device_uid", "device_secret", "temperature", "humidity",
                        "timestamp", "sequence"}
    if not isinstance(payload, dict) or not required_fields.issubset(payload.keys()):
        return False, "missing_required_fields"

    try:
        temperature = float(payload["temperature"])
        humidity = float(payload["humidity"])
        sequence = int(payload["sequence"])
        timestamp = float(payload["timestamp"])
    except (TypeError, ValueError):
        return False, "invalid_field_type"

    # Physically implausible values are rejected outright (distinct from
    # "anomalous but plausible" values, which are accepted but flagged).
    if not (-40.0 <= temperature <= 85.0):
        return False, "temperature_out_of_physical_range"
    if not (0.0 <= humidity <= 100.0):
        return False, "humidity_out_of_physical_range"
    if sequence < 0:
        return False, "invalid_sequence"

    return True, "ok"


def _check_replay(device_row, sequence: int, timestamp: float):
    """
    Reject messages that reuse or go backwards in sequence number (replay of a
    previously captured message), or whose timestamp is stale beyond the
    configured tolerance (clock-skew / captured-and-delayed replay).
    """
    if sequence <= device_row["last_sequence"]:
        return False, "replayed_or_out_of_order_sequence"

    age = abs(time.time() - timestamp)
    if age > config.MAX_MESSAGE_AGE_SECONDS:
        return False, "stale_timestamp_possible_replay"

    return True, "ok"


def _detect_anomaly(temperature: float, humidity: float) -> bool:
    return (
        temperature < config.TEMPERATURE_MIN_C
        or temperature > config.TEMPERATURE_MAX_C
        or humidity < config.HUMIDITY_MIN_PCT
        or humidity > config.HUMIDITY_MAX_PCT
    )


def _forward_to_backend(record: dict):
    """
    Forward a processed reading to the backend server.
    In this single-process prototype the backend runs in the same
    application, so we write directly via the shared database module
    (functionally equivalent to the authenticated HTTPS POST to
    /api/internal/sensor-data that a physically separate edge gateway
    would perform — see README.md for the real-deployment HTTP version).
    """
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO SensorData (device_id, temperature, humidity, status) "
        "VALUES (?, ?, ?, ?)",
        (record["device_id"], record["temperature"], record["humidity"],
         record["status"]),
    )
    conn.commit()
    return cur.lastrowid


def _raise_alert(device_id, reading_id, alert_type, severity, message):
    conn = get_db()
    conn.execute(
        "INSERT INTO Alerts (device_id, reading_id, alert_type, severity, message) "
        "VALUES (?, ?, ?, ?, ?)",
        (device_id, reading_id, alert_type, severity, message),
    )
    conn.commit()
    log_event("system", device_id, f"alert_raised:{alert_type}", message)


def handle_incoming_message(topic: str, payload: dict):
    """
    The MQTT message handler registered with the (simulated) broker.
    This is the single entry point that implements the full edge pipeline.
    """
    device_uid = payload.get("device_uid", "unknown") if isinstance(payload, dict) else "unknown"

    # --- Step 1: structural validation (before trusting any field) ---------
    is_valid, reason = _validate_payload(payload)
    if not is_valid:
        log_event("device", device_uid, "data_validation_failed", reason)
        return

    # --- Step 2: device authentication --------------------------------------
    device_row = authenticate_device(payload["device_uid"], payload["device_secret"])
    if device_row is None:
        # Deliberately vague to the caller; full reason is in the audit log.
        return

    # --- Step 3: per-device rate limiting (DoS / flooding mitigation) ------
    if is_device_rate_limited(device_row["device_uid"]):
        mark_device_suspicious(device_row["device_uid"],
                                "exceeded per-device message rate limit")
        return

    # --- Step 4: replay-attack protection -----------------------------------
    ok, reason = _check_replay(device_row, int(payload["sequence"]), float(payload["timestamp"]))
    if not ok:
        log_event("device", device_uid, "replay_attack_suspected", reason)
        mark_device_suspicious(device_row["device_uid"], reason)
        return

    conn = get_db()
    conn.execute("UPDATE Devices SET last_sequence = ? WHERE device_id = ?",
                 (int(payload["sequence"]), device_row["device_id"]))
    conn.commit()

    # --- Step 5: local processing / anomaly detection -----------------------
    temperature = float(payload["temperature"])
    humidity = float(payload["humidity"])
    is_anomalous = _detect_anomaly(temperature, humidity)

    count = _consecutive_anomalies.get(device_row["device_uid"], 0)
    count = count + 1 if is_anomalous else 0
    _consecutive_anomalies[device_row["device_uid"]] = count

    status = "anomalous" if is_anomalous else "normal"

    # --- Step 6/8: store (and, in a distributed deployment, forward) --------
    reading_id = _forward_to_backend({
        "device_id": device_row["device_id"],
        "temperature": temperature,
        "humidity": humidity,
        "status": status,
    })

    # --- Step 7: alert generation --------------------------------------------
    if is_anomalous and count >= config.ANOMALY_CONFIRMATION_COUNT:
        _raise_alert(
            device_row["device_id"], reading_id, "threshold_breach", "high",
            f"Device {device_row['device_uid']} reported temperature={temperature}\u00b0C, "
            f"humidity={humidity}% (outside configured safe range)."
        )

    log_event("device", device_row["device_uid"], "reading_processed",
              f"temp={temperature} humidity={humidity} status={status}")


def start_edge_gateway():
    """Subscribe the message handler to every device topic pattern used by the simulator."""
    broker.subscribe(f"{TOPIC_PREFIX}/publish", handle_incoming_message)
    log_event("system", "edge_gateway", "started", "Edge gateway subscribed to device topic")
