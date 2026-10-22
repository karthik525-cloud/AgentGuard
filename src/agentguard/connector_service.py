
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
    service = os.environ.get(
        "AGENTGUARD_KEYCHAIN_SERVICE", DEFAULT_SERVICE
    )
    account = os.environ.get(
        "AGENTGUARD_KEYCHAIN_ACCOUNT", DEFAULT_ACCOUNT
    )

    # Authorization policy must be configured by the trusted operator.
    configured_actions = os.environ.get(
        "AGENTGUARD_ALLOWED_ACTION_IDS"
    )

    if not configured_actions:
        print(
            json.dumps({"error": "Authorization policy is missing."}),
            file=sys.stderr,
        )
        return 2

    allowed_action_ids = {
        item.strip()
        for item in configured_actions.split(",")
        if item.strip()
    }

    if not allowed_action_ids:
        print(
            json.dumps({"error": "Authorization policy is empty."}),
            file=sys.stderr,
        )
        return 2

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
            json.dumps({
                "error": "Could not load signing key from Keychain."
            }),
            file=sys.stderr,
        )
        return 2

    try:
        request_line = sys.stdin.readline()
        if not request_line:
            raise ValueError("Request is empty")

        request = json.loads(request_line)

        if not isinstance(request, dict):
            raise ValueError("Request must be a JSON object")

        action_id = request.get("action_id")

        if not isinstance(action_id, str) or not action_id.strip():
            raise ValueError("action_id must be a non-empty string")

        # Reject unauthorized actions before reading database evidence.
        if action_id not in allowed_action_ids:
            raise PermissionError

        envelope = read_and_sign_booking(
            Path(db_path),
            action_id,
            secret_key,
            allowed_action_ids=allowed_action_ids,
        )

        print(json.dumps({
            "found": envelope is not None,
            "envelope": envelope,
        }))
        return 0

    except PermissionError:
        print(
            json.dumps({
                "error": "Request is not authorized for this action."
            }),
            file=sys.stderr,
        )
        return 1
    except (ValueError, TypeError, OSError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
