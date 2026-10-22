import unittest

from agentguard import EvidenceRecord, Verdict, verify_claim


class VerifyClaimTests(unittest.TestCase):
    def setUp(self):
        self.claim = {
            "action_id": "booking-1",
            "claimed_state": "confirmed",
        }
        self.evidence = EvidenceRecord(
            action_id="booking-1",
            source="booking-system",
            record_id="record-1",
            observed_state="confirmed",
        )

    def test_matching_evidence_verifies_claim(self):
        result = verify_claim(self.claim, [self.evidence])
        self.assertEqual(result["verdict"], Verdict.VERIFIED.value)

    def test_contradictory_evidence_fails_claim(self):
        evidence = EvidenceRecord(
            action_id="booking-1",
            source="booking-system",
            record_id="record-1",
            observed_state="failed",
        )
        result = verify_claim(self.claim, [evidence])
        self.assertEqual(result["verdict"], Verdict.FAILED.value)

    def test_missing_evidence_is_inconclusive(self):
        result = verify_claim(self.claim, [])
        self.assertEqual(result["verdict"], Verdict.INCONCLUSIVE.value)

    def test_plain_dictionary_is_not_connector_evidence(self):
        fake_evidence = {
            "action_id": "booking-1",
            "source": "agent-narrative",
            "record_id": "fake-record",
            "observed_state": "confirmed",
            "trusted": True,
            "independent": True,
        }
        result = verify_claim(self.claim, [fake_evidence])
        self.assertEqual(result["verdict"], Verdict.INCONCLUSIVE.value)

    def test_evidence_for_another_action_is_ignored(self):
        unrelated = EvidenceRecord(
            action_id="booking-2",
            source="booking-system",
            record_id="record-2",
            observed_state="confirmed",
        )
        result = verify_claim(self.claim, [unrelated])
        self.assertEqual(result["verdict"], Verdict.INCONCLUSIVE.value)

    def test_conflicting_evidence_is_inconclusive(self):
        second = EvidenceRecord(
            action_id="booking-1",
            source="audit-log",
            record_id="record-2",
            observed_state="failed",
        )
        result = verify_claim(self.claim, [self.evidence, second])
        self.assertEqual(result["verdict"], Verdict.INCONCLUSIVE.value)

    def test_missing_action_id_is_rejected(self):
        with self.assertRaises(ValueError):
            verify_claim({"claimed_state": "confirmed"}, [])

    def test_missing_claimed_state_is_rejected(self):
        with self.assertRaises(ValueError):
            verify_claim({"action_id": "booking-1"}, [])

    def test_non_dictionary_claim_is_rejected(self):
        with self.assertRaises(ValueError):
            verify_claim(None, [])


if __name__ == "__main__":
    unittest.main()
