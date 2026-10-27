"""Deterministic tool-using agent demo with independent verification."""

import json
import tempfile
from pathlib import Path

from agentguard import (
    InMemoryAuditLog,
    SQLiteBookingEvidenceProvider,
    record_booking,
    verify_agent_claim,
)


def deterministic_mock_agent() -> dict[str, str]:
    """Return a deliberately false success claim; this is not an LLM."""
    return {
        "action_id": "booking-agent-demo",
        "claimed_state": "confirmed",
    }


def main() -> None:
    with tempfile.TemporaryDirectory() as directory:
        database = Path(directory) / "booking-tool.db"
        # The controlled local tool records the actual failed outcome.
        record_booking(
            database,
            "booking-agent-demo",
            "record-agent-demo",
            "failed",
        )
        audit = InMemoryAuditLog()
        result = verify_agent_claim(
            deterministic_mock_agent(),
            SQLiteBookingEvidenceProvider(database),
            audit_sink=audit,
        )

        print(json.dumps(result, indent=2))
        print("AUDIT EVENTS:")
        for event in audit.events:
            print(json.dumps(event.__dict__, sort_keys=True))


if __name__ == "__main__":
    main()
