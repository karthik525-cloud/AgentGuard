import tempfile
import unittest
from pathlib import Path

from agentguard import record_booking, verify_signed_from_sqlite


class SignedSQLiteTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "bookings.db"
        self.key = b"agentguard-sqlite-test-key-at-least-32-bytes"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_matching_claim_is_verified(self):
        record_booking(
            self.db_path, "booking-1", "record-1", "confirmed"
        )
        result = verify_signed_from_sqlite(
            {"action_id": "booking-1", "claimed_state": "confirmed"},
            self.db_path,
            self.key,
        )
        self.assertEqual(result["verdict"], "VERIFIED")
        self.assertEqual(
            result["evidence_used"][0]["source"],
            "sqlite-booking-database",
        )

    def test_contradictory_claim_fails(self):
        record_booking(
            self.db_path, "booking-2", "record-2", "failed"
        )
        result = verify_signed_from_sqlite(
            {"action_id": "booking-2", "claimed_state": "confirmed"},
            self.db_path,
            self.key,
        )
        self.assertEqual(result["verdict"], "FAILED")

    def test_missing_booking_is_inconclusive(self):
        result = verify_signed_from_sqlite(
            {"action_id": "missing", "claimed_state": "confirmed"},
            self.db_path,
            self.key,
        )
        self.assertEqual(result["verdict"], "INCONCLUSIVE")

    def test_invalid_key_is_rejected(self):
        record_booking(
            self.db_path, "booking-3", "record-3", "confirmed"
        )
        with self.assertRaises(ValueError):
            verify_signed_from_sqlite(
                {"action_id": "booking-3", "claimed_state": "confirmed"},
                self.db_path,
                b"short",
            )


if __name__ == "__main__":
    unittest.main()
