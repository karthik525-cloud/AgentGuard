import unittest

from agentguard.evidence_signing import (
    sign_evidence,
    verify_signed_evidence,
)


class EvidenceSigningTests(unittest.TestCase):
    def setUp(self):
        self.secret_key = b"test-only-secret-key-at-least-32-bytes"
        self.evidence = {
            "action_id": "booking-1",
            "source": "booking-system",
            "record_id": "record-1",
            "observed_state": "confirmed",
        }

    def test_valid_signature_is_accepted(self):
        envelope = sign_evidence(self.evidence, self.secret_key)
        self.assertTrue(
            verify_signed_evidence(envelope, self.secret_key)
        )

    def test_modified_evidence_is_rejected(self):
        envelope = sign_evidence(self.evidence, self.secret_key)
        envelope["evidence"]["observed_state"] = "failed"
        self.assertFalse(
            verify_signed_evidence(envelope, self.secret_key)
        )

    def test_wrong_key_is_rejected(self):
        envelope = sign_evidence(self.evidence, self.secret_key)
        wrong_key = b"a-different-test-key-at-least-32-bytes"
        self.assertFalse(
            verify_signed_evidence(envelope, wrong_key)
        )

    def test_malformed_envelope_is_rejected(self):
        self.assertFalse(
            verify_signed_evidence({"evidence": [], "signature": "bad"}, self.secret_key)
        )

    def test_short_key_is_rejected(self):
        with self.assertRaises(ValueError):
            sign_evidence(self.evidence, b"short")

    def test_non_dictionary_evidence_is_rejected(self):
        with self.assertRaises(ValueError):
            sign_evidence(["not", "a", "dictionary"], self.secret_key)


if __name__ == "__main__":
    unittest.main()
