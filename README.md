# Secure Smart Environment Monitoring System (SSEMS)

A working prototype implementing the secure edge computing architecture
designed in Chapters One–Three of the accompanying final-year project
report: **"Design and Implementation of a Secure Edge Computing
Architecture for IoT Application."**

IoT devices (simulated, in place of physical ESP32 hardware) publish
temperature/humidity readings which are authenticated, validated,
processed, and monitored by an **Edge Gateway** before being stored and
exposed through a **Flask backend** and a **role-based web dashboard**.

---

## 1. What this prototype actually does

- **IoT layer** (`iot/simulator.py`): simulates 3 sensor nodes publishing
  readings every few seconds, occasionally injecting anomalous values and
  occasional *rogue* (impersonation) publish attempts, so the security
  controls below have something real to react to.
- **Secure communication**: messages are published/consumed through a
  publish/subscribe interface (`edge/mqtt_broker_sim.py`) that mirrors the
  real MQTT model (topics, `publish`/`subscribe`). See Section 7 for how to
  swap this for a real, TLS-secured Mosquitto broker.
- **Edge Gateway** (`edge/gateway.py`): authenticates every device,
  rate-limits per-device message rates, rejects replayed/out-of-order
  messages, validates data structure/ranges, detects threshold-based
  anomalies, stores readings, raises alerts, and writes security/audit
  logs — before data ever reaches the backend/dashboard.
- **Backend + Database** (`backend/`, `database/`): a Flask REST API
  backed by SQLite, with hashed passwords, hashed device secrets,
  Role-Based Access Control (admin/user), session management, and a
  generic per-IP API rate limiter.
- **Web Dashboard** (`dashboard/`): Bootstrap + Chart.js interface for
  login, an overview page, sensor-data trends, device management,
  alerts, the audit log, and user management — matching the interface
  designs proposed in Chapter Three, Section 3.13.

This is a **single-machine prototype**: for local demonstration and
grading convenience, the edge gateway and backend run in the same Python
process. The modules are nonetheless cleanly separated (see each file's
docstring) specifically so they *could* be split across a Raspberry Pi
(edge) and a separate server (backend) with minimal changes — see Section 7.

---

## 2. Requirements

- Python 3.9+
- No external services required to run the default demo (no Mosquitto,
  no internet access needed) — everything needed is either in the Python
  standard library or in `requirements.txt`.

Install dependencies:

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

---

## 3. Running the system

```bash
python app.py
```

You should see:

```
Default admin login: admin / ChangeMe!123
Dashboard: http://127.0.0.1:5000/login
```

Open that URL in a browser. **Change the default admin password's use
immediately** by creating a new admin user from the Users page and
retiring the seeded account, since this default exists only to let you
log in for the first time.

The IoT simulator and edge gateway start automatically in background
threads as soon as the app starts — you will see sensor data and
occasional alerts appear on the dashboard within a few seconds, with no
further action needed.

### Running with HTTPS (optional, recommended for demonstrating TLS)

```bash
bash certs/generate_self_signed_cert.sh
python app.py --https
```

Your browser will warn that the certificate is self-signed (expected —
this is a local demonstration certificate, not one from a trusted CA).
Accept the warning to proceed. This demonstrates the same TLS mechanism
(`ssl_context`) that a real deployment would use with a CA-issued
certificate.

### Running the automated tests

```bash
python -m unittest discover -s tests -v
```

26 unit tests cover password hashing, input validation, device
authentication, replay-attack detection, anomaly detection, and the login
rate limiter.

---

## 4. Default account and demo data

| Username | Password      | Role  |
|----------|---------------|-------|
| admin    | ChangeMe!123  | admin |

Three simulated devices ("Simulated Sensor 1/2/3") are auto-registered on
first run. Their secrets are generated fresh each run and are **not**
recoverable from the database (only their hash is stored) — this is
intentional and mirrors how a real device's credential would be handled.
If you stop and restart the app, delete `database/ssems.db` first if you
want a clean slate with new simulated devices; otherwise the app will
reuse the existing database and register any additional devices needed to
reach the configured count.

---

## 5. Where each security control lives

| Control | Location |
|---|---|
| Password hashing (PBKDF2, salted) | `security/auth.py` |
| Device credential hashing | `security/device_auth.py` |
| Role-Based Access Control | `security/auth.py` (`role_required`), enforced in `backend/api.py` |
| Session management (sliding timeout) | `security/auth.py` |
| Login brute-force lockout | `security/rate_limit.py`, used in `backend/views.py` |
| Per-device flood/DoS mitigation | `security/rate_limit.py`, used in `edge/gateway.py` |
| Generic API rate limiting | `security/rate_limit.py`, `backend/api.py` (`before_request`) |
| Input/data validation | `edge/gateway.py` (`_validate_payload`), `backend/api.py` |
| Replay-attack protection | `edge/gateway.py` (`_check_replay`), sequence number + timestamp freshness |
| Anomaly detection | `edge/gateway.py` (`_detect_anomaly`) |
| Security/audit logging | `database/db.py` (`log_event`), called throughout |
| TLS/HTTPS | `certs/`, `app.py` (`--https` flag) |

---

## 6. Deploying on Render

This app runs on Render as an ordinary Python web service. The repo already
includes what Render needs (`Procfile`, `render.yaml`, `gunicorn` in
`requirements.txt`) — you can either click through the manual steps below or
use the included `render.yaml` Blueprint.

### Manual setup

1. Push this project to a GitHub/GitLab repository.
2. On Render: **New + → Web Service**, connect the repo.
3. **Build Command**: `pip install -r requirements.txt`
4. **Start Command**: `gunicorn app:app --workers 1 --threads 4 --timeout 120 --bind 0.0.0.0:$PORT`
   - **Use exactly `--workers 1`.** The rate limiter, replay-protection
     sequence tracking, and the IoT simulator all keep their state in memory
     inside one process. Multiple worker *processes* would each run their
     own independent copy of that state (and their own simulator threads),
     which breaks rate limiting and would register duplicate simulated
     devices. `--threads 4` still gives you concurrency for multiple
     dashboard users within that one worker.
5. **Environment Variables** (Render dashboard → Environment):
   - `SSEMS_SECRET_KEY` — generate a random value (Render can auto-generate
     one for you) and never reuse the `dev-placeholder-change-me` default.
   - `SSEMS_FORCE_SECURE_COOKIES` = `true` — Render serves your app over
     HTTPS automatically, so tell Flask to mark session cookies `Secure`.
6. Deploy. Render gives you a `https://<your-app>.onrender.com` URL —
   Render terminates TLS for you at the edge, so you do **not** need the
   self-signed certificate/`--https` flag from Section 3; that's only for
   running HTTPS locally.

### Using the included `render.yaml` instead

On Render: **New + → Blueprint**, point it at this repository. Render reads
`render.yaml` and pre-fills the build/start commands and environment
variables described above.

### About the database on Render

Render's **free** web-service plan has an **ephemeral filesystem**: every
deploy, restart, or scale event wipes `database/ssems.db` and the app
re-seeds a fresh default admin and simulated devices. That's fine for a
demo/grading link, but not for data you want to keep. Two ways to fix that:

- **Render persistent Disk** (paid plans only): attach a Disk mounted at
  `/var/data`, set the environment variable `SSEMS_DB_PATH=/var/data/ssems.db`,
  and the SQLite file survives redeploys. The commented-out block at the
  bottom of `render.yaml` shows exactly this.
- **Managed Postgres** (more work, more realistic for a real deployment):
  Render offers a free Postgres instance; you'd change `database/db.py` to
  use `psycopg2`/`SQLAlchemy` instead of `sqlite3`. Not required for this
  prototype/demo, but the natural next step mentioned in Section 7 below.

## 7. Moving from this prototype to a physically distributed deployment

This prototype intentionally runs on one machine for ease of setup and
grading. To deploy it as originally architected — ESP32 devices, a
Raspberry Pi edge gateway, and a separate backend server:

1. **Real MQTT broker**: install Mosquitto on the Raspberry Pi, configure
   it with a password file and TLS certificates. Replace
   `edge/mqtt_broker_sim.py`'s `SimulatedMQTTBroker` with a thin adapter
   using `paho-mqtt` (`pip install paho-mqtt`):
   ```python
   import paho.mqtt.client as mqtt
   client = mqtt.Client()
   client.tls_set(ca_certs="ca.crt")
   client.username_pw_set(device_uid, device_secret)
   client.connect("edge-gateway-host", 8883)
   ```
   `edge/gateway.py` and `iot/simulator.py` only call `publish`/`subscribe`,
   so no other code needs to change.
2. **Physical ESP32 devices**: replace `iot/simulator.py` with ESP32
   firmware (Arduino/MicroPython) that reads a DHT22 sensor and publishes
   the same JSON payload shape (`device_uid`, `device_secret`,
   `temperature`, `humidity`, `timestamp`, `sequence`) over MQTT/TLS.
3. **Separate backend server**: change `edge/gateway.py`'s
   `_forward_to_backend()` from a direct database write to an authenticated
   HTTPS POST to a `/api/internal/sensor-data` endpoint on the backend
   server (add this endpoint to `backend/api.py`, protected by a
   gateway-specific API key or mutual TLS).
4. **Production database**: swap SQLite for PostgreSQL by changing
   `database/db.py`'s connection logic; the schema in `database/schema.sql`
   is written in standard SQL and needs only minor type adjustments
   (e.g., `SERIAL` instead of `AUTOINCREMENT`).
5. **Production WSGI server**: run the Flask app behind Gunicorn/uWSGI and
   a reverse proxy (e.g., Nginx) terminating TLS, instead of Flask's
   built-in development server.

---

## 8. Security assumptions and limitations (read before citing this as "secure")

Consistent with Chapter One, Section 1.8 and academic honesty requirements,
this prototype is a **teaching/demonstration system, not a hardened
production system**. Specifically:

- The MQTT layer is **simulated in-process** for portability; it does not
  exercise real network-level TLS handshakes, certificate validation, or
  Mosquitto's own access-control lists. Section 7 shows how to close this
  gap for a real deployment.
- Rate limiting and session state are held **in-memory**, so they reset on
  restart and do not scale across multiple backend processes/machines.
- The self-signed TLS certificate is for local demonstration only and is
  not trusted by browsers by default — a real deployment requires a
  CA-issued certificate.
- Security testing performed against this system (see Chapter Five) is
  limited to simulated, non-destructive scenarios in a local development
  environment; it is not a substitute for a professional penetration test
  or security audit.
- No system can be claimed as completely secure; this project aims to
  demonstrate the correct application of standard controls (authentication,
  encryption, validation, RBAC, rate limiting, logging), not to guarantee
  invulnerability.

---

## 9. Project structure

```
ssems_project/
├── app.py                     # Entry point: wires everything together
├── requirements.txt
├── certs/
│   └── generate_self_signed_cert.sh
├── config/
│   └── config.py              # Thresholds, secrets, rate-limit settings
├── database/
│   ├── schema.sql
│   └── db.py
├── security/
│   ├── auth.py                # User auth, hashing, sessions, RBAC
│   ├── device_auth.py         # Device registration & authentication
│   └── rate_limit.py          # Login lockout, device & API rate limits
├── edge/
│   ├── mqtt_broker_sim.py     # Simulated pub/sub broker (swap for Mosquitto)
│   └── gateway.py             # Validation, anomaly detection, alerts, logging
├── iot/
│   └── simulator.py           # Simulated sensor devices + rogue-device demo
├── backend/
│   ├── views.py                # Page routes (login, dashboard, etc.)
│   └── api.py                  # JSON REST API
├── dashboard/
│   ├── templates/               # Jinja2 HTML (Bootstrap-based)
│   └── static/{css,js}/
└── tests/
    ├── test_auth.py
    ├── test_security.py
    └── test_validation.py
```
