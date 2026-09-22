"""
iot/simulator.py
------------------
Simulates one or more IoT sensor nodes publishing temperature/humidity
readings over the (simulated) MQTT link, in the absence of physical ESP32
hardware, per the simulation approach described in Chapter Three, Section 3.6.

Each simulated cycle:
  - every registered simulated device publishes a normal or (occasionally,
    deliberately) anomalous reading, correctly authenticated;
  - with a small probability, one additional message is published using a
    WRONG device secret ("rogue device"), to demonstrate that the edge
    gateway's authentication step correctly rejects impersonation attempts.
"""

import random
import time
import threading

from config import config
from database.db import get_db, log_event
from security.device_auth import register_device
from edge.mqtt_broker_sim import broker
from edge.gateway import TOPIC_PREFIX

_sequence_counters = {}
_stop_flag = threading.Event()


def _ensure_simulated_devices(admin_user_id: int):
    """Register the configured number of simulated devices if they don't already exist."""
    conn = get_db()
    existing = conn.execute(
        "SELECT device_uid FROM Devices WHERE device_name LIKE 'Simulated Sensor%'"
    ).fetchall()
    devices = []
    if existing:
        for row in existing:
            # We cannot recover the plaintext secret (only its hash is stored),
            # so simulated devices created on a previous run are skipped; new
            # ones are created to reach the configured count.
            pass
    count_needed = config.SIMULATED_DEVICE_COUNT - len(existing)
    for i in range(max(count_needed, 0)):
        name = f"Simulated Sensor {len(existing) + i + 1}"
        device_uid, device_secret = register_device(name, admin_user_id)
        devices.append({"device_uid": device_uid, "device_secret": device_secret,
                         "name": name})
        _sequence_counters[device_uid] = 0
        print(f"[simulator] Registered {name} -> {device_uid}")

    # Re-fetch all simulated devices; for previously-existing ones we do not
    # have the plaintext secret, so only newly created devices in this run
    # can actually publish authenticated data (documented behaviour: this
    # matters only across separate app restarts, not during one run).
    return devices


def _publish_normal_or_anomalous(device_uid, device_secret):
    seq = _sequence_counters.get(device_uid, 0) + 1
    _sequence_counters[device_uid] = seq

    if random.random() < config.SIMULATED_ANOMALY_PROBABILITY:
        temperature = random.choice([random.uniform(-10, 9), random.uniform(46, 60)])
        humidity = random.choice([random.uniform(0, 9), random.uniform(91, 100)])
    else:
        temperature = round(random.uniform(20.0, 30.0), 2)
        humidity = round(random.uniform(40.0, 60.0), 2)

    payload = {
        "device_uid": device_uid,
        "device_secret": device_secret,
        "temperature": round(temperature, 2),
        "humidity": round(humidity, 2),
        "timestamp": time.time(),
        "sequence": seq,
    }
    broker.publish(f"{TOPIC_PREFIX}/publish", payload)


def _publish_rogue_attempt(real_device_uid):
    """Simulate an attacker impersonating a known device with a wrong secret."""
    seq = _sequence_counters.get(real_device_uid, 0) + 1
    payload = {
        "device_uid": real_device_uid,
        "device_secret": "WRONG-SECRET-INJECTED-BY-ATTACKER",
        "temperature": 25.0,
        "humidity": 50.0,
        "timestamp": time.time(),
        "sequence": seq,
    }
    log_event("system", "simulator", "rogue_publish_attempt_injected",
              f"Simulated impersonation of {real_device_uid} for demonstration purposes")
    broker.publish(f"{TOPIC_PREFIX}/publish", payload)


def _simulation_loop(devices):
    while not _stop_flag.is_set():
        for dev in devices:
            _publish_normal_or_anomalous(dev["device_uid"], dev["device_secret"])
        if devices and random.random() < config.SIMULATED_ROGUE_ATTEMPT_PROBABILITY:
            _publish_rogue_attempt(random.choice(devices)["device_uid"])
        _stop_flag.wait(config.SIMULATION_INTERVAL_SECONDS)


def start_simulator(admin_user_id: int):
    devices = _ensure_simulated_devices(admin_user_id)
    if not devices:
        print("[simulator] No new simulated devices to run this session "
              "(existing ones lack recoverable secrets). "
              "Delete database/ssems.db to reset and re-seed.")
        return
    thread = threading.Thread(target=_simulation_loop, args=(devices,), daemon=True)
    thread.start()
    log_event("system", "simulator", "started",
              f"{len(devices)} simulated device(s) publishing every "
              f"{config.SIMULATION_INTERVAL_SECONDS}s")


def stop_simulator():
    _stop_flag.set()
