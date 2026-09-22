"""
tests/test_security.py
------------------------
Unit tests for device authentication (security/device_auth.py) using a
temporary, isolated SQLite database, and for the edge gateway's replay-attack
protection logic (edge/gateway.py).
"""

import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Point the app at a throwaway database BEFORE importing modules that use it.
from config import config
_tmp_dir = tempfile.mkdtemp()
config.DATABASE_PATH = os.path.join(_tmp_dir, "test_ssems.db")

from database.db import init_db
from security.device_auth import register_device, authenticate_device
from edge.gateway import _check_replay


class TestDeviceAuthentication(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        cls.device_uid, cls.device_secret = register_device("Test Device", 1)

    def test_correct_credentials_succeed(self):
        row = authenticate_device(self.device_uid, self.device_secret)
        self.assertIsNotNone(row)
        self.assertEqual(row["device_uid"], self.device_uid)

    def test_wrong_secret_fails(self):
        row = authenticate_device(self.device_uid, "wrong-secret")
        self.assertIsNone(row)

    def test_unknown_device_fails(self):
        row = authenticate_device("dev-does-not-exist", "anything")
        self.assertIsNone(row)


class TestReplayProtection(unittest.TestCase):
    def test_higher_sequence_accepted(self):
        device_row = {"last_sequence": 5}
        ok, _ = _check_replay(device_row, 6, time.time())
        self.assertTrue(ok)

    def test_repeated_sequence_rejected(self):
        device_row = {"last_sequence": 5}
        ok, reason = _check_replay(device_row, 5, time.time())
        self.assertFalse(ok)
        self.assertEqual(reason, "replayed_or_out_of_order_sequence")

    def test_lower_sequence_rejected(self):
        device_row = {"last_sequence": 10}
        ok, reason = _check_replay(device_row, 3, time.time())
        self.assertFalse(ok)

    def test_stale_timestamp_rejected(self):
        device_row = {"last_sequence": 1}
        old_timestamp = time.time() - (config.MAX_MESSAGE_AGE_SECONDS + 30)
        ok, reason = _check_replay(device_row, 2, old_timestamp)
        self.assertFalse(ok)
        self.assertEqual(reason, "stale_timestamp_possible_replay")


if __name__ == "__main__":
    unittest.main()
