"""
app.py
-------
Entry point for the Secure Smart Environment Monitoring System (SSEMS)
prototype. Run with:

    python app.py

This single process hosts, for convenience of local demonstration and
grading, all three logical tiers described in Chapter Three:
  - the Edge Gateway (edge/gateway.py) subscribed to the simulated MQTT
    broker (edge/mqtt_broker_sim.py),
  - the IoT device simulator (iot/simulator.py),
  - the Backend server + REST API + Web Dashboard (backend/, dashboard/).

Running them as one process is a deliberate simplification for a
single-machine undergraduate demonstration; the modules are still cleanly
separated (see each module's docstring) and could be split across a
Raspberry Pi (edge) and a separate host (backend) with minimal changes —
mainly replacing the direct function calls in edge/gateway.py's
`_forward_to_backend` with an authenticated HTTPS POST, and swapping
edge/mqtt_broker_sim.py for a real paho-mqtt client against Mosquitto
(see README.md).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask

from config import config
from database.db import init_db, get_db
from backend.views import views
from backend.api import api
from edge.gateway import start_edge_gateway
from iot.simulator import start_simulator


def create_app():
    app = Flask(
        __name__,
        template_folder=os.path.join("dashboard", "templates"),
        static_folder=os.path.join("dashboard", "static"),
    )
    app.secret_key = config.SECRET_KEY
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        # True when served over HTTPS: local --https flag, or in production via
        # SSEMS_FORCE_SECURE_COOKIES=true (see README, "Deploying on Render").
        SESSION_COOKIE_SECURE=config.FORCE_SECURE_COOKIES,
    )

    app.register_blueprint(views)
    app.register_blueprint(api)

    return app


def bootstrap():
    """Initialize the database and start the edge gateway + IoT simulator."""
    init_db()
    start_edge_gateway()

    conn = get_db()
    admin = conn.execute(
        "SELECT user_id FROM Users WHERE role = 'admin' ORDER BY user_id LIMIT 1"
    ).fetchone()
    admin_id = admin["user_id"] if admin else 1
    start_simulator(admin_id)


app = create_app()

with app.app_context():
    bootstrap()


if __name__ == "__main__":
    use_https = "--https" in sys.argv
    ssl_context = None
    scheme = "http"

    if use_https:
        cert_path = os.path.join("certs", "cert.pem")
        key_path = os.path.join("certs", "key.pem")
        if os.path.exists(cert_path) and os.path.exists(key_path):
            ssl_context = (cert_path, key_path)
            scheme = "https"
            app.config["SESSION_COOKIE_SECURE"] = True
        else:
            print("[warn] --https requested but certs/cert.pem or certs/key.pem "
                  "not found. Run: bash certs/generate_self_signed_cert.sh")
            print("[warn] Falling back to HTTP.")

    port = int(os.environ.get("PORT", 5000))  # hosting platforms set PORT

    print("=" * 70)
    print(" Secure Smart Environment Monitoring System (SSEMS) — Prototype")
    print("=" * 70)
    print(f" Default admin login: {config.DEFAULT_ADMIN_USERNAME} / "
          f"{config.DEFAULT_ADMIN_PASSWORD}")
    print(" >>> CHANGE THE DEFAULT PASSWORD IMMEDIATELY AFTER FIRST LOGIN <<<")
    print(f" Dashboard: {scheme}://127.0.0.1:{port}/login")
    print("=" * 70)
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False,
             ssl_context=ssl_context)
