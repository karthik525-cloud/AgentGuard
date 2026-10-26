import concurrent.futures
import hashlib
import hmac
import json
import tempfile
import unittest
import uuid
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agentguard import (
    ReplayDetectedError,
    SQLiteReplayStore,
    sign_evidence,
    verify_and_consume_claim,
    verify_signed_claim,
    verify_signed_evidence,
)


class ReplayProtectionTests(unittest.TestCase):
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
        self.temp_dir = tempfile.TemporaryDirectory()
        self.store_path = Path(self.temp_dir.name) / "replay.db"
        self.store = SQLiteReplayStore(self.store_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def consume(self, envelope, *, store=None, expected_action_id="booking-1"):
        return verify_and_consume_claim(
            self.claim,
            envelope,
            self.key,
            store or self.store,
            expected_action_id=expected_action_id,
        )

    def manually_sign(self, payload):
        signature = hmac.new(
            self.key,
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return {"evidence": payload, "signature": signature}

    def test_first_consumption_succeeds_and_duplicate_is_rejected(self):
        envelope = sign_evidence(self.evidence, self.key)

        result = self.consume(envelope)
        self.assertEqual(result["verdict"], "VERIFIED")
        self.assertTrue(self.store.is_consumed(envelope["evidence"]["evidence_id"]))

        with self.assertRaises(ReplayDetectedError):
            self.consume(envelope)

    def test_action_mismatch_is_not_consumed(self):
        envelope = sign_evidence(self.evidence, self.key)

        with self.assertRaisesRegex(ValueError, "does not match"):
            self.consume(envelope, expected_action_id="booking-2")

        self.assertFalse(self.store.is_consumed(envelope["evidence"]["evidence_id"]))
        self.assertEqual(self.consume(envelope)["verdict"], "VERIFIED")

    def test_invalid_or_expired_evidence_is_not_consumed(self):
        envelope = sign_evidence(self.evidence, self.key)
        tampered = deepcopy(envelope)
        tampered["evidence"]["observed_state"] = "failed"

        with self.assertRaisesRegex(ValueError, "valid signature"):
            self.consume(tampered)
        self.assertFalse(self.store.is_consumed(envelope["evidence"]["evidence_id"]))
        self.assertEqual(self.consume(envelope)["verdict"], "VERIFIED")

        expired = sign_evidence(
            dict(
                self.evidence,
                timestamp=(
                    datetime.now(timezone.utc) - timedelta(minutes=10)
                ).isoformat(),
            ),
            self.key,
        )
        with self.assertRaisesRegex(ValueError, "valid signature"):
            self.consume(expired)
        self.assertFalse(self.store.is_consumed(expired["evidence"]["evidence_id"]))

    def test_legacy_envelope_remains_read_only_but_cannot_be_consumed(self):
        legacy = self.manually_sign(
            dict(
                self.evidence,
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
        )

        result = verify_signed_claim(self.claim, [legacy], self.key)
        self.assertEqual(result["verdict"], "VERIFIED")

        with self.assertRaisesRegex(ValueError, "evidence_id"):
            self.consume(legacy)

    def test_validly_signed_non_uuid4_ids_are_not_consumed(self):
        for evidence_id in ("not-a-uuid", str(uuid.uuid1())):
            with self.subTest(evidence_id=evidence_id):
                envelope = self.manually_sign(
                    dict(
                        self.evidence,
                        evidence_id=evidence_id,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                    )
                )
                self.assertTrue(verify_signed_evidence(envelope, self.key))

                with self.assertRaisesRegex(ValueError, "canonical UUID4"):
                    self.consume(envelope)

                self.assertFalse(self.store.is_consumed(evidence_id))

    def test_consumption_persists_across_store_instances(self):
        envelope = sign_evidence(self.evidence, self.key)
        self.consume(envelope)
        restarted_store = SQLiteReplayStore(self.store_path)

        with self.assertRaises(ReplayDetectedError):
            self.consume(envelope, store=restarted_store)

    def test_concurrent_consumption_has_one_winner(self):
        envelope = sign_evidence(self.evidence, self.key)

        def attempt():
            store = SQLiteReplayStore(self.store_path)
            try:
                self.consume(envelope, store=store)
                return "consumed"
            except ReplayDetectedError:
                return "replayed"

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            outcomes = list(executor.map(lambda _: attempt(), range(8)))

        self.assertEqual(outcomes.count("consumed"), 1)
        self.assertEqual(outcomes.count("replayed"), 7)


if __name__ == "__main__":
    unittest.main()
