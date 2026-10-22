
"""Local connector service for AgentGuard."""

import json
import os
import sys
from pathlib import Path

from .keychain_store import (
    DEFAULT_ACCOUNT,
    DEFAULT_SERVICE,
    load_key,
)
from .trusted_connector import read_and_sign_booking


def main() -> int:
    db_path = os.environ.get("AGENTGUARD_DB_PATH")
    service = os.environ.get("AGENTGUARD_KEYCHAIN_SERVICE", DEFAULT_SERVICE)
    account = os.environ.get("AGENTGUARD_KEYCHAIN_ACCOUNT", DEFAULT_ACCOUNT)

    if not db_path:
        print(
            json.dumps({"error": "Database configuration is missing."}),
            file=sys.stderr,
        )
        return 2

    try:
        secret_key = load_key(service=service, account=account)
    except RuntimeError:
        print(
            json.dumps({"error": "Could not load signing key from Keychain."}),
            file=sys.stderr,
        )
        return 2

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
