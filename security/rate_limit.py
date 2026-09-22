"""
security/rate_limit.py
------------------------
A minimal fixed-window rate limiter used to mitigate brute-force login
attempts, excessive/flooding device publishes, and generic API abuse
(DoS-like behaviour). Implemented in-memory for prototype purposes; a
production deployment would typically back this with Redis or similar
shared storage across multiple backend instances.
"""

import time
import threading
from collections import defaultdict, deque

from config import config
from database.db import log_event

_lock = threading.Lock()
_login_attempts = defaultdict(deque)     # key: ip -> timestamps
_login_lockout_until = {}                # key: ip -> unlock timestamp
_device_messages = defaultdict(deque)    # key: device_uid -> timestamps
_api_requests = defaultdict(deque)       # key: ip -> timestamps


def _prune(dq: deque, window_seconds: float):
    now = time.time()
    while dq and now - dq[0] > window_seconds:
        dq.popleft()


def is_login_locked_out(ip: str) -> bool:
    with _lock:
        unlock_at = _login_lockout_until.get(ip)
        if unlock_at and time.time() < unlock_at:
            return True
        if unlock_at and time.time() >= unlock_at:
            del _login_lockout_until[ip]
        return False


def register_login_attempt(ip: str, success: bool):
    """Track a login attempt; trigger a temporary lockout after too many failures."""
    with _lock:
        if success:
            _login_attempts[ip].clear()
            return
        dq = _login_attempts[ip]
        _prune(dq, config.LOGIN_WINDOW_SECONDS)
        dq.append(time.time())
        if len(dq) >= config.LOGIN_MAX_ATTEMPTS:
            _login_lockout_until[ip] = time.time() + config.LOGIN_LOCKOUT_SECONDS
            log_event("system", ip, "login_lockout_triggered",
                      f"{len(dq)} failed attempts within "
                      f"{config.LOGIN_WINDOW_SECONDS}s")


def is_device_rate_limited(device_uid: str) -> bool:
    """Return True if a device is publishing faster than the configured limit."""
    with _lock:
        dq = _device_messages[device_uid]
        _prune(dq, config.DEVICE_WINDOW_SECONDS)
        dq.append(time.time())
        if len(dq) > config.DEVICE_MAX_MESSAGES:
            log_event("system", device_uid, "device_rate_limit_exceeded",
                       f"{len(dq)} messages within {config.DEVICE_WINDOW_SECONDS}s")
            return True
        return False


def is_api_rate_limited(ip: str) -> bool:
    with _lock:
        dq = _api_requests[ip]
        _prune(dq, config.API_WINDOW_SECONDS)
        dq.append(time.time())
        if len(dq) > config.API_MAX_REQUESTS:
            log_event("system", ip, "api_rate_limit_exceeded",
                       f"{len(dq)} requests within {config.API_WINDOW_SECONDS}s")
            return True
        return False
