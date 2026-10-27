import tempfile
import unittest
from pathlib import Path

import agentguard


class PublicAPITests(unittest.TestCase):
    def test_public_exports_are_available(self):
        self.assertTrue(callable(agentguard.verify_claim))
        self.assertTrue(callable(agentguard.verify_from_sqlite))
        self.assertTrue(callable(agentguard.record_booking))
        self.assertTrue(callable(agentguard.verify_and_consume_claim))
        self.assertTrue(callable(agentguard.verify_agent_claim))
        self.assertTrue(callable(agentguard.AuditEvent))
        self.assertTrue(callable(agentguard.AuditSink))
        self.assertTrue(callable(agentguard.EvidenceProvider))
        self.assertTrue(callable(agentguard.SQLiteBookingEvidenceProvider))
        self.assertTrue(callable(agentguard.InMemoryAuditLog))
        self.assertTrue(callable(agentguard.SQLiteReplayStore))
        self.assertTrue(issubclass(agentguard.ReplayDetectedError, RuntimeError))
        self.assertTrue(callable(agentguard.EvidenceRecord))
        self.assertEqual(agentguard.__version__, "0.1.0")

    def test_public_verification_function(self):
        evidence = agentguard.EvidenceRecord(
            action_id="task-1",
            source="task-database",
            record_id="record-1",
            observed_state="completed",
        )
        result = agentguard.verify_claim(
            {
                "action_id": "task-1",
                "claimed_state": "completed",
            },
            [evidence],
        )
        self.assertEqual(result["verdict"], "VERIFIED")

    def test_public_sqlite_integration(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "test.db"
            agentguard.record_booking(
                db_path, "booking-1", "record-1", "failed"
            )
            result = agentguard.verify_from_sqlite(
                {
                    "action_id": "booking-1",
                    "claimed_state": "confirmed",
                },
                db_path,
            )
            self.assertEqual(result["verdict"], "FAILED")
            self.assertEqual(
                result["evidence_used"][0]["record_id"], "record-1"
            )


if __name__ == "__main__":
    unittest.main()
