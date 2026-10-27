import tempfile
import unittest
import uuid
from pathlib import Path

from agentguard import (
    EvidenceRecord,
    InMemoryAuditLog,
    SQLiteBookingEvidenceProvider,
    record_booking,
    verify_agent_claim,
)


class RaisingProvider:
    def collect_evidence(self, action_id):
        raise RuntimeError("sensitive provider failure")


class RaisingAuditSink:
    def emit(self, event):
        raise RuntimeError("audit storage unavailable")


class AgentIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "bookings.db"
        self.claim = {
            "action_id": "booking-agent-1",
            "claimed_state": "confirmed",
        }

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_false_agent_success_is_failed_and_audited(self):
        record_booking(
            self.db_path,
            "booking-agent-1",
            "record-agent-1",
            "failed",
        )
        audit = InMemoryAuditLog()

        result = verify_agent_claim(
            self.claim,
            SQLiteBookingEvidenceProvider(self.db_path),
            audit_sink=audit,
        )

        self.assertEqual(result["verdict"], "FAILED")
        self.assertEqual(audit.events[0].reason_code, "claim_received")
        decision = audit.events[-1]
        self.assertEqual(decision.event_type, "verification_decision")
        self.assertEqual(decision.action_id, "booking-agent-1")
        self.assertEqual(decision.verdict, "FAILED")
        self.assertEqual(decision.reason_code, "claim_contradicted")
        self.assertEqual(uuid.UUID(decision.event_id).version, 4)
        self.assertIn("+00:00", decision.timestamp)

    def test_matching_independent_evidence_verifies_claim(self):
        record_booking(
            self.db_path,
            "booking-agent-1",
            "record-agent-1",
            "confirmed",
        )

        result = verify_agent_claim(
            self.claim,
            SQLiteBookingEvidenceProvider(self.db_path),
        )

        self.assertEqual(result["verdict"], "VERIFIED")

    def test_missing_evidence_is_inconclusive_and_audited(self):
        audit = InMemoryAuditLog()

        result = verify_agent_claim(
            self.claim,
            SQLiteBookingEvidenceProvider(self.db_path),
            audit_sink=audit,
        )

        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertEqual(audit.events[-1].reason_code, "evidence_missing")

    def test_provider_failure_is_inconclusive_without_logging_details(self):
        audit = InMemoryAuditLog()

        result = verify_agent_claim(
            self.claim,
            RaisingProvider(),
            audit_sink=audit,
        )

        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertEqual(
            [event.reason_code for event in audit.events],
            ["claim_received", "evidence_collection_failed", "evidence_missing"],
        )
        self.assertNotIn("sensitive provider failure", repr(audit.events))

    def test_audit_failure_cannot_change_a_failed_verdict(self):
        record_booking(
            self.db_path,
            "booking-agent-1",
            "record-agent-1",
            "failed",
        )

        result = verify_agent_claim(
            self.claim,
            SQLiteBookingEvidenceProvider(self.db_path),
            audit_sink=RaisingAuditSink(),
        )

        self.assertEqual(result["verdict"], "FAILED")

    def test_invalid_claim_is_logged_without_untrusted_action_id(self):
        audit = InMemoryAuditLog()

        with self.assertRaises(ValueError):
            verify_agent_claim(
                {"action_id": "", "claimed_state": "confirmed"},
                SQLiteBookingEvidenceProvider(self.db_path),
                audit_sink=audit,
            )

        self.assertEqual(audit.events[0].reason_code, "invalid_claim")
        self.assertIsNone(audit.events[0].action_id)

    def test_plain_dictionary_from_provider_is_not_accepted_as_evidence(self):
        class UntrustedProvider:
            def collect_evidence(self, action_id):
                return {"action_id": action_id, "observed_state": "confirmed"}

        result = verify_agent_claim(self.claim, UntrustedProvider())

        self.assertEqual(result["verdict"], "INCONCLUSIVE")


if __name__ == "__main__":
    unittest.main()
