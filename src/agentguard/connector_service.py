
"""Local trusted connector service for AgentGuard."""

import json
import os
import sys
from pathlib import Path

from .trusted_connector import read_and_sign_booking


def main() -> int:
    db_path = os.environ.get("AGENTGUARD_DB_PATH")
    key_hex = os.environ.get("AGENTGUARD_SIGNING_KEY")

    if not db_path or not key_hex:
        print(
            json.dumps({"error": "Connector configuration is missing."}),
            file=sys.stderr,
        )
        return 2

    try:
        secret_key = bytes.fromhex(key_hex)
    except ValueError:
        print(
            json.dumps({"error": "Signing key must be valid hexadecimal."}),
            file=sys.stderr,
        )
        return 2

    if len(secret_key) < 32:
        print(
            json.dumps({"error": "Signing key must be at least 32 bytes."}),
            file=sys.stderr,
        )
        return 2

    # Accept one JSON request from standard input.
    try:
        request = json.loads(sys.stdin.readline())
        if not isinstance(request, dict):
            raise ValueError("Request must be a JSON object")

        action_id = request.get("action_id")
        if not isinstance(action_id, str) or not action_id.strip():
            raise ValueError("action_id must be a non-empty string")

        envelope = read_and_sign_booking(
            Path(db_path), action_id, secret_key
        )

        print(json.dumps({
            "found": envelope is not None,
            "envelope": envelope,
        }))
        return 0

    except (ValueError, TypeError, OSError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
