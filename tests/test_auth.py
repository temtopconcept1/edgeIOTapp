"""
tests/test_auth.py
--------------------
Unit tests for password hashing, username/password validation, and the
login rate limiter. Run with:  python -m pytest tests/  (or python -m unittest)
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import config
config.DATABASE_PATH = os.path.join(tempfile.mkdtemp(), "test_ssems_auth.db")

from database.db import init_db
from security.auth import hash_password, verify_password, is_valid_username, \
    is_valid_password
from security.rate_limit import register_login_attempt, is_login_locked_out

init_db()


class TestPasswordHashing(unittest.TestCase):
    def test_hash_is_not_plaintext(self):
        h = hash_password("MySecretPass1")
        self.assertNotEqual(h, "MySecretPass1")

    def test_verify_correct_password(self):
        h = hash_password("MySecretPass1")
        self.assertTrue(verify_password("MySecretPass1", h))

    def test_verify_wrong_password(self):
        h = hash_password("MySecretPass1")
        self.assertFalse(verify_password("WrongPassword", h))

    def test_two_hashes_of_same_password_differ(self):
        # Confirms salting is in effect (no two hashes should be identical).
        h1 = hash_password("SamePassword1")
        h2 = hash_password("SamePassword1")
        self.assertNotEqual(h1, h2)


class TestInputValidation(unittest.TestCase):
    def test_valid_username(self):
        self.assertTrue(is_valid_username("admin_01"))

    def test_username_too_short(self):
        self.assertFalse(is_valid_username("ab"))

    def test_username_rejects_special_chars(self):
        self.assertFalse(is_valid_username("admin;DROP TABLE Users;"))

    def test_password_minimum_length(self):
        self.assertFalse(is_valid_password("short"))
        self.assertTrue(is_valid_password("longenough1"))


class TestLoginRateLimiter(unittest.TestCase):
    def test_lockout_triggers_after_max_attempts(self):
        ip = "10.0.0.99"
        for _ in range(config.LOGIN_MAX_ATTEMPTS):
            register_login_attempt(ip, success=False)
        self.assertTrue(is_login_locked_out(ip))

    def test_successful_login_clears_attempts(self):
        ip = "10.0.0.100"
        register_login_attempt(ip, success=False)
        register_login_attempt(ip, success=True)
        self.assertFalse(is_login_locked_out(ip))


if __name__ == "__main__":
    unittest.main()
