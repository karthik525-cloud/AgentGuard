
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agentguard import record_booking, verify_signed_evidence
from agentguard.connector_service import main


class ConnectorServiceTests(unittest.TestCase):
    def setUp(self):
        self.key = os.urandom(32)
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "bookings.db"

        record_booking(
            self.db_path,
            "booking-service-1",
            "record-service-1",
            "confirmed",
        )

        self.env = os.environ.copy()
        self.env["AGENTGUARD_DB_PATH"] = str(self.db_path)
        self.env["AGENTGUARD_ALLOWED_ACTION_IDS"] = "booking-service-1"
        self.env.pop("AGENTGUARD_SIGNING_KEY", None)

    def tearDown(self):
        self.temp_dir.cleanup()

    def run_service(self, request):
        return self.run_service_bytes(
            (json.dumps(request) + "\n").encode("utf-8")
        )

    def run_service_bytes(self, payload):
        stdout = io.StringIO()
        stderr = io.StringIO()
        stdin = io.TextIOWrapper(io.BytesIO(payload), encoding="utf-8")

        with (
            patch.dict(os.environ, self.env, clear=True),
            patch("sys.stdin", stdin),
            patch("sys.stdout", stdout),
            patch("sys.stderr", stderr),
            patch("agentguard.connector_service.load_key", return_value=self.key),
        ):
            returncode = main()

        return subprocess.CompletedProcess(
            ["agentguard.connector_service"],
            returncode,
            stdout.getvalue(),
            stderr.getvalue(),
        )

    def test_service_returns_signed_booking_evidence(self):
        result = self.run_service(
            {"action_id": "booking-service-1"}
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        response = json.loads(result.stdout)
        self.assertTrue(response["found"])

        envelope = response["envelope"]
        self.assertEqual(
            envelope["evidence"]["observed_state"],
            "confirmed",
        )
        self.assertTrue(
            verify_signed_evidence(envelope, self.key),
            "Connector returned an invalid signature",
        )

    def test_service_rejects_unauthorized_action(self):
        result = self.run_service(
            {"action_id": "booking-not-allowed"}
        )

        self.assertEqual(result.returncode, 1)
        response = json.loads(result.stderr)
        self.assertEqual(
            response["error"],
            "Request is not authorized for this action.",
        )

    def test_service_fails_when_authorization_policy_is_missing(self):
        self.env.pop("AGENTGUARD_ALLOWED_ACTION_IDS", None)

        result = self.run_service(
            {"action_id": "booking-service-1"}
        )

        self.assertEqual(result.returncode, 2)
        response = json.loads(result.stderr)
        self.assertEqual(
            response["error"],
            "Authorization policy is missing.",
        )

    def test_service_rejects_empty_input(self):
        result = self.run_service_bytes(b"")

        self.assertEqual(result.returncode, 1)
        response = json.loads(result.stderr)
        self.assertEqual(response["error"], "Request is empty")

    def test_service_rejects_malformed_json(self):
        result = self.run_service_bytes(b"{not-json}\n")

        self.assertEqual(result.returncode, 1)
        response = json.loads(result.stderr)
        self.assertEqual(
            response["error"],
            "Request contains invalid JSON.",
        )

    def test_service_rejects_non_object_json(self):
        result = self.run_service_bytes(b'["booking-service-1"]\n')

        self.assertEqual(result.returncode, 1)
        response = json.loads(result.stderr)
        self.assertEqual(
            response["error"],
            "Request must be a JSON object",
        )

    def test_service_rejects_unexpected_fields(self):
        result = self.run_service(
            {
                "action_id": "booking-service-1",
                "extra": "field",
            }
        )

        self.assertEqual(result.returncode, 1)
        response = json.loads(result.stderr)
        self.assertEqual(
            response["error"],
            "Request must contain only the action_id field",
        )

    def test_service_rejects_oversized_input(self):
        result = self.run_service_bytes(b"x" * 1025)

        self.assertEqual(result.returncode, 1)
        response = json.loads(result.stderr)
        self.assertEqual(
            response["error"],
            "Request exceeds the size limit",
        )

    def test_service_rejects_oversized_multibyte_utf8_input(self):
        # 513 two-byte characters are 1026 bytes, but under 1024 characters.
        result = self.run_service_bytes("é".encode("utf-8") * 513)

        self.assertEqual(result.returncode, 1)
        response = json.loads(result.stderr)
        self.assertEqual(
            response["error"],
            "Request exceeds the size limit",
        )

    def test_service_rejects_action_id_longer_than_200_characters(self):
        result = self.run_service({"action_id": "a" * 201})

        self.assertEqual(result.returncode, 1)
        response = json.loads(result.stderr)
        self.assertEqual(
            response["error"],
            "action_id must be a non-empty string of at most 200 characters",
        )

    def test_service_rejects_action_id_with_surrounding_whitespace(self):
        result = self.run_service(
            {"action_id": " booking-service-1 "}
        )

        self.assertEqual(result.returncode, 1)
        response = json.loads(result.stderr)
        self.assertEqual(
            response["error"],
            "action_id must be a non-empty string of at most 200 characters",
        )

    def test_service_accepts_valid_request_without_trailing_newline(self):
        result = self.run_service_bytes(
            json.dumps({"action_id": "booking-service-1"}).encode("utf-8")
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        response = json.loads(result.stdout)
        self.assertTrue(response["found"])
        self.assertTrue(
            verify_signed_evidence(response["envelope"], self.key),
            "Connector returned an invalid signature",
        )


if __name__ == "__main__":
    unittest.main()
