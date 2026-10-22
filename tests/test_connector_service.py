
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
    def test_service_returns_signed_booking_evidence(self):
        key = os.urandom(32)

        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "bookings.db"

            record_booking(
                db_path,
                "booking-service-1",
                "record-service-1",
                "confirmed",
            )

            try:
                store_key(key, service=TEST_SERVICE, account=TEST_ACCOUNT)

                env = os.environ.copy()
                env["PYTHONPATH"] = str(
                    Path(__file__).resolve().parents[1] / "src"
                )
                env["AGENTGUARD_DB_PATH"] = str(db_path)
                env["AGENTGUARD_KEYCHAIN_SERVICE"] = TEST_SERVICE
                env["AGENTGUARD_KEYCHAIN_ACCOUNT"] = TEST_ACCOUNT
                env.pop("AGENTGUARD_SIGNING_KEY", None)

                result = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "agentguard.connector_service",
                    ],
                    input=json.dumps(
                        {"action_id": "booking-service-1"}
                    ) + "\n",
                    text=True,
                    capture_output=True,
                    env=env,
                    check=False,
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
                    verify_signed_evidence(envelope, key),
                    "Connector returned an invalid signature",
                )

            finally:
                delete_key(service=TEST_SERVICE, account=TEST_ACCOUNT)


if __name__ == "__main__":
    unittest.main()
