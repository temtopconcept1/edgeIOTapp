"""
config/config.py
-----------------
Central configuration for the Secure Smart Environment Monitoring System (SSEMS).

IMPORTANT (academic honesty note):
All values below are placeholders/defaults suitable for a local development
and demonstration environment. Replace SECRET_KEY and any credentials before
any deployment beyond local testing. Nothing in this file should be treated
as production-grade secret material.
"""

import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# --- Flask / session configuration -----------------------------------------
SECRET_KEY = os.environ.get("SSEMS_SECRET_KEY", "dev-placeholder-change-me")
SESSION_TIMEOUT_MINUTES = 30

# --- Database ----------------------------------------------------------------
# Overridable via SSEMS_DB_PATH so a hosting platform's persistent disk mount
# (e.g. Render Disks at /var/data) can be used instead of the repo folder,
# which is wiped on every redeploy on most platforms' ephemeral filesystems.
DATABASE_PATH = os.environ.get(
    "SSEMS_DB_PATH", os.path.join(BASE_DIR, "database", "ssems.db")
)

# --- Deployment / cookies -----------------------------------------------------
# Set SSEMS_FORCE_SECURE_COOKIES=true when served over HTTPS (Render, or any
# platform terminating TLS in front of the app) so session cookies are only
# ever sent over an encrypted connection.
FORCE_SECURE_COOKIES = os.environ.get(
    "SSEMS_FORCE_SECURE_COOKIES", "false"
).lower() == "true"

# --- Edge gateway / anomaly-detection thresholds -----------------------------
TEMPERATURE_MIN_C = 10.0
TEMPERATURE_MAX_C = 45.0
HUMIDITY_MIN_PCT = 10.0
HUMIDITY_MAX_PCT = 90.0

# Consecutive out-of-range readings before an alert is raised (reduces noise
# from single transient spikes while still reacting quickly).
ANOMALY_CONFIRMATION_COUNT = 1

# --- Replay-attack protection -------------------------------------------------
# Maximum allowed clock skew (seconds) between a message's declared timestamp
# and the edge gateway's local time. Messages outside this window are rejected.
MAX_MESSAGE_AGE_SECONDS = 60

# --- Rate limiting -------------------------------------------------------------
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 60          # per-IP login attempts per window
LOGIN_LOCKOUT_SECONDS = 120        # lockout duration after exceeding attempts

DEVICE_MAX_MESSAGES = 20
DEVICE_WINDOW_SECONDS = 10         # per-device message rate limit (anti-flood/DoS)

API_MAX_REQUESTS = 60
API_WINDOW_SECONDS = 60            # generic per-IP API rate limit

# --- IoT simulation ------------------------------------------------------------
SIMULATED_DEVICE_COUNT = 3
SIMULATION_INTERVAL_SECONDS = 5
# Probability that a given simulated reading is deliberately anomalous,
# used to demonstrate anomaly detection during testing/demonstration.
SIMULATED_ANOMALY_PROBABILITY = 0.12
# Probability that the simulator additionally emits one rogue/unauthenticated
# publish attempt in a given cycle, to demonstrate device-authentication
# rejection and security logging.
SIMULATED_ROGUE_ATTEMPT_PROBABILITY = 0.15

# --- Default administrator account (created on first run if no users exist) ---
DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "ChangeMe!123"   # MUST be changed after first login
