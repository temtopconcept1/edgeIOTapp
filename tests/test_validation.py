"""
tests/test_validation.py
--------------------------
Unit tests for the edge gateway's data-validation and anomaly-detection
logic (edge/gateway.py). These test pure functions only and do not require
a running database or broker.
"""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from edge.gateway import _validate_payload, _detect_anomaly


def base_payload(**overrides):
    payload = {
        "device_uid": "dev-test",
        "device_secret": "irrelevant-for-structural-validation",
        "temperature": 24.5,
        "humidity": 55.0,
        "timestamp": time.time(),
        "sequence": 1,
    }
    payload.update(overrides)
    return payload


class TestPayloadValidation(unittest.TestCase):
    def test_valid_payload_passes(self):
        ok, reason = _validate_payload(base_payload())
        self.assertTrue(ok, reason)

    def test_missing_field_rejected(self):
        payload = base_payload()
        del payload["temperature"]
        ok, reason = _validate_payload(payload)
        self.assertFalse(ok)
        self.assertEqual(reason, "missing_required_fields")

    def test_non_numeric_temperature_rejected(self):
        ok, reason = _validate_payload(base_payload(temperature="not-a-number"))
        self.assertFalse(ok)
        self.assertEqual(reason, "invalid_field_type")

    def test_physically_impossible_temperature_rejected(self):
        ok, reason = _validate_payload(base_payload(temperature=999))
        self.assertFalse(ok)
        self.assertEqual(reason, "temperature_out_of_physical_range")

    def test_negative_sequence_rejected(self):
        ok, reason = _validate_payload(base_payload(sequence=-1))
        self.assertFalse(ok)
        self.assertEqual(reason, "invalid_sequence")

    def test_not_a_dict_rejected(self):
        ok, reason = _validate_payload("not-a-dict")
        self.assertFalse(ok)


class TestAnomalyDetection(unittest.TestCase):
    def test_normal_reading_not_anomalous(self):
        self.assertFalse(_detect_anomaly(25.0, 50.0))

    def test_high_temperature_is_anomalous(self):
        self.assertTrue(_detect_anomaly(70.0, 50.0))

    def test_low_humidity_is_anomalous(self):
        self.assertTrue(_detect_anomaly(25.0, 2.0))


if __name__ == "__main__":
    unittest.main()
