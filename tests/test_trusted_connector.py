import tempfile
import unittest
from pathlib import Path

from agentguard import record_booking, verify_signed_evidence
from agentguard.trusted_connector import read_and_sign_booking


class TrustedConnectorTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "bookings.db"
        self.key = b"trusted-connector-test-key-at-least-32-bytes"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_reads_and_signs_database_evidence(self):
        record_booking(
            self.db_path, "booking-1", "record-1", "confirmed"
        )

        envelope = read_and_sign_booking(
            self.db_path, "booking-1", self.key
        )

        self.assertIsNotNone(envelope)
        self.assertTrue(verify_signed_evidence(envelope, self.key))
        self.assertEqual(
            envelope["evidence"]["observed_state"], "confirmed"
        )
        self.assertEqual(
            envelope["evidence"]["record_id"], "record-1"
        )

    def test_missing_booking_returns_none(self):
        result = read_and_sign_booking(
            self.db_path, "missing", self.key
        )
        self.assertIsNone(result)

    def test_modified_envelope_fails_signature_check(self):
        record_booking(
            self.db_path, "booking-2", "record-2", "failed"
        )
        envelope = read_and_sign_booking(
            self.db_path, "booking-2", self.key
        )
        envelope["evidence"]["observed_state"] = "confirmed"

        self.assertFalse(verify_signed_evidence(envelope, self.key))

    def test_short_key_is_rejected(self):
        with self.assertRaises(ValueError):
            read_and_sign_booking(
                self.db_path, "booking-1", b"short"
            )


if __name__ == "__main__":
    unittest.main()
