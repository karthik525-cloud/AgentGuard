import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEMO_PATH = PROJECT_ROOT / "examples" / "demo.json"


class CLITests(unittest.TestCase):
    def setUp(self):
        self.env = os.environ.copy()
        self.env["PYTHONPATH"] = str(PROJECT_ROOT / "src")
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def run_cli(self, scenario_path):
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "agentguard.cli",
                str(scenario_path),
            ],
            capture_output=True,
            text=True,
            env=self.env,
            cwd=PROJECT_ROOT,
            check=False,
        )

    def write_scenario(self, payload):
        path = Path(self.temp_dir.name) / "scenario.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_demo_json_returns_failed(self):
        result = self.run_cli(DEMO_PATH)

        self.assertEqual(result.returncode, 1, result.stderr)
        response = json.loads(result.stdout)
        self.assertEqual(response["verdict"], "FAILED")
        self.assertEqual(response["action_id"], "booking-1042")
        self.assertEqual(
            response["evidence_used"][0]["observed_state"],
            "failed",
        )

    def test_matching_scenario_returns_verified(self):
        result = self.run_cli(
            self.write_scenario(
                {
                    "claim": {
                        "action_id": "booking-1",
                        "claimed_state": "confirmed",
                    },
                    "evidence": [
                        {
                            "action_id": "booking-1",
                            "source": "booking-system",
                            "record_id": "record-1",
                            "observed_state": "confirmed",
                        }
                    ],
                }
            )
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        response = json.loads(result.stdout)
        self.assertEqual(response["verdict"], "VERIFIED")

    def test_missing_evidence_field_returns_error(self):
        result = self.run_cli(
            self.write_scenario(
                {
                    "claim": {
                        "action_id": "booking-1",
                        "claimed_state": "confirmed",
                    },
                    "evidence": [
                        {
                            "action_id": "booking-1",
                            "source": "booking-system",
                            "observed_state": "confirmed",
                        }
                    ],
                }
            )
        )

        self.assertEqual(result.returncode, 2)
        response = json.loads(result.stderr)
        self.assertEqual(
            response["error"],
            "Evidence is missing required field: record_id",
        )

    def test_invalid_json_returns_error(self):
        path = Path(self.temp_dir.name) / "invalid.json"
        path.write_text("{not-json", encoding="utf-8")

        result = self.run_cli(path)

        self.assertEqual(result.returncode, 2)
        response = json.loads(result.stderr)
        self.assertIn("error", response)
        self.assertTrue(response["error"])

    def test_missing_top_level_field_returns_error(self):
        result = self.run_cli(
            self.write_scenario(
                {
                    "claim": {
                        "action_id": "booking-1",
                        "claimed_state": "confirmed",
                    }
                }
            )
        )

        self.assertEqual(result.returncode, 2)
        response = json.loads(result.stderr)
        self.assertEqual(
            response["error"],
            "Scenario is missing the evidence field",
        )


if __name__ == "__main__":
    unittest.main()
