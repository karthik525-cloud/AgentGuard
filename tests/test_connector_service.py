
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from agentguard import record_booking, verify_signed_evidence
from agentguard.keychain_store import store_key, delete_key


TEST_SERVICE = "AgentGuard.SigningKey.Tests"
TEST_ACCOUNT = "agentguard-connector-tests"


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

        store_key(
            self.key,
            service=TEST_SERVICE,
            account=TEST_ACCOUNT,
        )

        self.env = os.environ.copy()
        self.env["PYTHONPATH"] = str(
            Path(__file__).resolve().parents[1] / "src"
        )
        self.env["AGENTGUARD_DB_PATH"] = str(self.db_path)
        self.env["AGENTGUARD_KEYCHAIN_SERVICE"] = TEST_SERVICE
        self.env["AGENTGUARD_KEYCHAIN_ACCOUNT"] = TEST_ACCOUNT
        self.env["AGENTGUARD_ALLOWED_ACTION_IDS"] = "booking-service-1"
        self.env.pop("AGENTGUARD_SIGNING_KEY", None)

    def tearDown(self):
        try:
            delete_key(service=TEST_SERVICE, account=TEST_ACCOUNT)
        finally:
            self.temp_dir.cleanup()

    def run_service(self, request):
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "agentguard.connector_service",
            ],
            input=json.dumps(request) + "\n",
            text=True,
            capture_output=True,
            env=self.env,
            check=False,
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


if __name__ == "__main__":
    unittest.main()
