"""Example: an AI agent checking its claim with AgentGuard."""

import tempfile
from pathlib import Path

from agentguard import record_booking, verify_from_sqlite


def simulated_ai_agent() -> dict:
    """Simulate an agent claiming a booking succeeded."""
    return {
        "action_id": "booking-2048",
        "claimed_state": "confirmed",
    }


def main() -> None:
    with tempfile.TemporaryDirectory() as directory:
        db_path = Path(directory) / "integration_demo.db"

        # Simulate the application recording the real outcome.
        # In this example, the booking actually failed.
        record_booking(
            db_path,
            action_id="booking-2048",
            record_id="reservation-9001",
            state="failed",
        )

        # The agent makes its claim.
        claim = simulated_ai_agent()
        print("Agent claim:", claim["claimed_state"])

        # AgentGuard independently reads the database record.
        result = verify_from_sqlite(claim, db_path)
        print("AgentGuard verdict:", result["verdict"])
        print("Reason:", result["reason"])
        print("Evidence:", result["evidence_used"])

        if result["verdict"] != "VERIFIED":
            print("Action must not be treated as successfully verified.")


if __name__ == "__main__":
    main()
