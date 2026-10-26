
import unittest
import uuid
from datetime import datetime, timedelta, timezone

from agentguard.evidence_signing import (
    sign_evidence,
    verify_signed_evidence,
    is_evidence_fresh,
)


class EvidenceSigningTests(unittest.TestCase):
    def setUp(self):
        self.key = b"agentguard-test-signing-key-at-least-32-bytes"

    def test_sign_and_verify_evidence(self):
        envelope = sign_evidence(
            {"action_id": "booking-1", "observed_state": "confirmed"},
            self.key,
        )
        self.assertTrue(verify_signed_evidence(envelope, self.key))

    def test_new_evidence_has_a_unique_signed_uuid4_id(self):
        first = sign_evidence({"action_id": "booking-1"}, self.key)
        second = sign_evidence({"action_id": "booking-1"}, self.key)

        first_id = first["evidence"]["evidence_id"]
        self.assertNotEqual(first_id, second["evidence"]["evidence_id"])
        self.assertEqual(uuid.UUID(first_id).version, 4)
        first["evidence"]["evidence_id"] = str(uuid.uuid4())
        self.assertFalse(verify_signed_evidence(first, self.key))

    def test_wrong_key_fails_verification(self):
        envelope = sign_evidence({"action_id": "booking-1"}, self.key)
        self.assertFalse(
            verify_signed_evidence(envelope, b"another-test-key-at-least-32-bytes")
        )

    def test_modified_payload_fails_verification(self):
        envelope = sign_evidence({"action_id": "booking-1"}, self.key)
        envelope["evidence"]["action_id"] = "booking-2"
        self.assertFalse(verify_signed_evidence(envelope, self.key))

    def test_invalid_envelope_fails_verification(self):
        self.assertFalse(verify_signed_evidence({}, self.key))
        self.assertFalse(
            verify_signed_evidence(
                {"evidence": [], "signature": "abc"}, self.key
            )
        )

    def test_short_key_is_rejected(self):
        with self.assertRaises(ValueError):
            sign_evidence({"action_id": "booking-1"}, b"short")

    def test_non_dictionary_evidence_is_rejected(self):
        with self.assertRaises(ValueError):
            sign_evidence([], self.key)

    def test_fresh_evidence_is_accepted(self):
        envelope = sign_evidence(
            {"action_id": "booking-1", "observed_state": "confirmed"},
            self.key,
        )
        self.assertTrue(is_evidence_fresh(envelope, self.key))

    def test_expired_evidence_is_rejected(self):
        old_time = (
            datetime.now(timezone.utc) - timedelta(minutes=10)
        ).isoformat()
        envelope = sign_evidence(
            {"action_id": "booking-1", "timestamp": old_time},
            self.key,
        )
        self.assertFalse(
            is_evidence_fresh(envelope, self.key, max_age_seconds=60)
        )

    def test_future_evidence_outside_clock_skew_is_rejected(self):
        future_time = (
            datetime.now(timezone.utc) + timedelta(minutes=5)
        ).isoformat()
        envelope = sign_evidence(
            {"action_id": "booking-1", "timestamp": future_time},
            self.key,
        )
        self.assertFalse(
            is_evidence_fresh(
                envelope,
                self.key,
                max_age_seconds=300,
                clock_skew_seconds=30,
            )
        )

    def test_tampered_evidence_is_not_fresh(self):
        envelope = sign_evidence({"action_id": "booking-1"}, self.key)
        envelope["evidence"]["observed_state"] = "confirmed"
        self.assertFalse(is_evidence_fresh(envelope, self.key))

    def test_replaced_signature_fails_verification(self):
        envelope = sign_evidence(
            {"action_id": "booking-1", "observed_state": "confirmed"},
            self.key,
        )
        envelope["signature"] = "0" * 64

        self.assertFalse(verify_signed_evidence(envelope, self.key))

    def test_signature_from_another_envelope_fails_verification(self):
        first = sign_evidence(
            {"action_id": "booking-1", "observed_state": "confirmed"},
            self.key,
        )
        second = sign_evidence(
            {"action_id": "booking-2", "observed_state": "cancelled"},
            self.key,
        )

        first["signature"] = second["signature"]

        self.assertFalse(verify_signed_evidence(first, self.key))

    def test_naive_timestamp_is_rejected(self):
        naive_timestamp = datetime.now().replace(tzinfo=None).isoformat()
        envelope = sign_evidence(
            {
                "action_id": "booking-1",
                "timestamp": naive_timestamp,
            },
            self.key,
        )

        self.assertFalse(is_evidence_fresh(envelope, self.key))


if __name__ == "__main__":
    unittest.main()
