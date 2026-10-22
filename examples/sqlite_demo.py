import json
import tempfile
from pathlib import Path

from agentguard.sqlite_source import record_booking, verify_from_sqlite


def main():
    with tempfile.TemporaryDirectory() as temp_dir:
        db_path = Path(temp_dir) / "bookings.db"

        # The real application record says the booking failed.
        record_booking(
            db_path,
            action_id="booking-1042",
            record_id="reservation-7781",
            state="failed",
        )

        # The AI agent incorrectly claims the booking was confirmed.
        claim = {
            "action_id": "booking-1042",
            "claimed_state": "confirmed",
        }

        result = verify_from_sqlite(claim, db_path)

        print("AGENT CLAIM:")
        print(json.dumps(claim, indent=2))
        print("\nAGENTGUARD VERIFICATION:")
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
