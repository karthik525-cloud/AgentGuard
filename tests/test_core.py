import unittest

from agentguard import verify_claim


class VerifyClaimTests(unittest.TestCase):
    def setUp(self):
        self.claim = {
            "action_id": "order-123",
            "claimed_state": "completed",
        }
        self.evidence = {
            "action_id": "order-123",
            "source": "order-database",
            "record_id": "db-row-7",
            "observed_state": "completed",
            "independent": True,
            "trusted": True,
        }

    def test_matching_independent_evidence_verifies_claim(self):
        result = verify_claim(self.claim, [self.evidence])
        self.assertEqual(result["verdict"], "VERIFIED")
        self.assertEqual(len(result["evidence_used"]), 1)

    def test_contradictory_evidence_fails_claim(self):
        evidence = {**self.evidence, "observed_state": "failed"}
        result = verify_claim(self.claim, [evidence])
        self.assertEqual(result["verdict"], "FAILED")

    def test_missing_evidence_is_inconclusive(self):
        result = verify_claim(self.claim, [])
        self.assertEqual(result["verdict"], "INCONCLUSIVE")

    def test_untrusted_evidence_is_not_used(self):
        evidence = {**self.evidence, "trusted": False}
        result = verify_claim(self.claim, [evidence])
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertEqual(result["evidence_used"], [])

    def test_agent_provided_evidence_is_not_independent(self):
        evidence = {**self.evidence, "independent": False}
        result = verify_claim(self.claim, [evidence])
        self.assertEqual(result["verdict"], "INCONCLUSIVE")

    def test_evidence_for_another_action_is_ignored(self):
        evidence = {**self.evidence, "action_id": "different-order"}
        result = verify_claim(self.claim, [evidence])
        self.assertEqual(result["verdict"], "INCONCLUSIVE")

    def test_conflicting_trusted_evidence_is_inconclusive(self):
        conflicting = {
            **self.evidence,
            "record_id": "db-row-8",
            "observed_state": "failed",
        }
        result = verify_claim(self.claim, [self.evidence, conflicting])
        self.assertEqual(result["verdict"], "INCONCLUSIVE")

    def test_missing_action_id_is_rejected(self):
        with self.assertRaises(ValueError):
            verify_claim({"claimed_state": "completed"}, [])

    def test_evidence_requires_a_record_identifier(self):
        evidence = {key: value for key, value in self.evidence.items()
                    if key != "record_id"}
        result = verify_claim(self.claim, [evidence])
        self.assertEqual(result["verdict"], "INCONCLUSIVE")


if __name__ == "__main__":
    unittest.main()
