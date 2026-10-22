import unittest

from agentguard import sign_evidence, verify_signed_claim


class SignedClaimTests(unittest.TestCase):
    def setUp(self):
        self.key = b"agentguard-test-key-at-least-32-bytes"
        self.claim = {
            "action_id": "booking-1",
            "claimed_state": "confirmed",
        }
        self.evidence = {
            "action_id": "booking-1",
            "source": "booking-system",
            "record_id": "record-1",
            "observed_state": "confirmed",
        }

    def test_valid_signed_evidence_verifies_claim(self):
        envelope = sign_evidence(self.evidence, self.key)
        result = verify_signed_claim(self.claim, [envelope], self.key)
        self.assertEqual(result["verdict"], "VERIFIED")

    def test_signed_contradiction_fails_claim(self):
        evidence = dict(self.evidence, observed_state="failed")
        envelope = sign_evidence(evidence, self.key)
        result = verify_signed_claim(self.claim, [envelope], self.key)
        self.assertEqual(result["verdict"], "FAILED")

    def test_tampered_evidence_is_inconclusive(self):
        envelope = sign_evidence(self.evidence, self.key)
        envelope["evidence"]["observed_state"] = "failed"
        result = verify_signed_claim(self.claim, [envelope], self.key)
        self.assertEqual(result["verdict"], "INCONCLUSIVE")

    def test_wrong_key_is_inconclusive(self):
        envelope = sign_evidence(self.evidence, self.key)
        wrong_key = b"wrong-test-key-at-least-32-bytes-long"
        result = verify_signed_claim(self.claim, [envelope], wrong_key)
        self.assertEqual(result["verdict"], "INCONCLUSIVE")

    def test_mixed_valid_and_invalid_evidence_ignores_invalid(self):
        valid = sign_evidence(self.evidence, self.key)
        invalid = sign_evidence(
            dict(self.evidence, record_id="record-2"), self.key
        )
        invalid["evidence"]["observed_state"] = "failed"

        result = verify_signed_claim(
            self.claim, [valid, invalid], self.key
        )
        self.assertEqual(result["verdict"], "VERIFIED")
        self.assertEqual(len(result["evidence_used"]), 1)


if __name__ == "__main__":
    unittest.main()
