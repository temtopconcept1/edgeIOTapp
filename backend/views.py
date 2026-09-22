"""
backend/views.py
------------------
Routes that render the HTML dashboard pages. Actual data is fetched by the
front-end JavaScript from the JSON API in backend/api.py; these routes only
handle page rendering and access control (redirecting unauthenticated users
to the login page, and gating admin-only pages).
"""

from flask import Blueprint, render_template, request, redirect, url_for, session

from security.auth import (
    authenticate_user, start_session, end_session, session_is_valid,
)
from security.rate_limit import is_login_locked_out, register_login_attempt

views = Blueprint("views", __name__)


@views.route("/login", methods=["GET", "POST"])
def login_page():
    if session_is_valid():
        return redirect(url_for("views.dashboard_page"))

    error = None
    if request.method == "POST":
        ip = request.remote_addr or "unknown"
        if is_login_locked_out(ip):
            error = "Too many failed attempts. Please try again in a moment."
        else:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = authenticate_user(username, password, ip)
            register_login_attempt(ip, success=user is not None)
            if user is None:
                error = "Invalid username or password."
            else:
                start_session(user)
                return redirect(url_for("views.dashboard_page"))

    return render_template("login.html", error=error)


@views.route("/logout")
def logout():
    end_session()
    return redirect(url_for("views.login_page"))


@views.route("/")
@views.route("/dashboard")
def dashboard_page():
    if not session_is_valid():
        return redirect(url_for("views.login_page"))
    return render_template("dashboard.html", role=session.get("role"),
                            username=session.get("username"))


@views.route("/devices")
def devices_page():
    if not session_is_valid():
        return redirect(url_for("views.login_page"))
    return render_template("devices.html", role=session.get("role"),
                            username=session.get("username"))


@views.route("/sensors")
def sensors_page():
    if not session_is_valid():
        return redirect(url_for("views.login_page"))
    return render_template("sensors.html", role=session.get("role"),
                            username=session.get("username"))


@views.route("/alerts")
def alerts_page():
    if not session_is_valid():
        return redirect(url_for("views.login_page"))
    return render_template("alerts.html", role=session.get("role"),
                            username=session.get("username"))


@views.route("/users")
def users_page():
    if not session_is_valid():
        return redirect(url_for("views.login_page"))
    if session.get("role") != "admin":
        return render_template("dashboard.html", role=session.get("role"),
                                username=session.get("username"),
                                forbidden_notice="User management is restricted "
                                                  "to administrators.")
    return render_template("users.html", role=session.get("role"),
                            username=session.get("username"))
