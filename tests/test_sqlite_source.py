import tempfile
import unittest
from pathlib import Path

from agentguard.sqlite_source import record_booking, verify_from_sqlite


class SQLiteSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "bookings.db"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_detects_false_booking_claim(self):
        record_booking(
            self.db_path, "booking-1", "row-1", "failed"
        )
        result = verify_from_sqlite(
            {"action_id": "booking-1", "claimed_state": "confirmed"},
            self.db_path,
        )
        self.assertEqual(result["verdict"], "FAILED")
        self.assertEqual(
            result["evidence_used"][0]["record_id"], "row-1"
        )

    def test_verifies_matching_claim(self):
        record_booking(
            self.db_path, "booking-2", "row-2", "confirmed"
        )
        result = verify_from_sqlite(
            {"action_id": "booking-2", "claimed_state": "confirmed"},
            self.db_path,
        )
        self.assertEqual(result["verdict"], "VERIFIED")

    def test_missing_database_is_inconclusive(self):
        result = verify_from_sqlite(
            {"action_id": "missing", "claimed_state": "confirmed"},
            self.db_path,
        )
        self.assertEqual(result["verdict"], "INCONCLUSIVE")

    def test_missing_booking_is_inconclusive(self):
        record_booking(
            self.db_path, "another-booking", "row-3", "confirmed"
        )
        result = verify_from_sqlite(
            {"action_id": "missing", "claimed_state": "confirmed"},
            self.db_path,
        )
        self.assertEqual(result["verdict"], "INCONCLUSIVE")


if __name__ == "__main__":
    unittest.main()
