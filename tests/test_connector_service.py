from agentguard import verify_signed_evidence
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from agentguard import record_booking


class ConnectorServiceTests(unittest.TestCase):
    def test_service_returns_signed_booking_evidence(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "bookings.db"
            key = os.urandom(32)

            record_booking(
                db_path, "booking-service-1", "record-service-1", "confirmed"
            )

            env = os.environ.copy()
            env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
            env["AGENTGUARD_DB_PATH"] = str(db_path)
            env["AGENTGUARD_SIGNING_KEY"] = key.hex()

            result = subprocess.run(
                [sys.executable, "-m", "agentguard.connector_service"],
                input=json.dumps({"action_id": "booking-service-1"}) + "\n",
                text=True,
                capture_output=True,
                env=env,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            response = json.loads(result.stdout)
            self.assertTrue(response["found"])
            self.assertEqual(
                response["envelope"]["evidence"]["observed_state"],
                "confirmed",
            )
            self.assertIn("signature", response["envelope"])
            self.assertTrue(
                verify_signed_evidence(response["envelope"], key),
                "Connector returned an invalid signature",
            )


if __name__ == "__main__":
    unittest.main()
