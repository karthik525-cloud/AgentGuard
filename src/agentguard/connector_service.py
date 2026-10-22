
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

MAX_REQUEST_BYTES = 1024


def emit_error(message: str, exit_code: int) -> int:
    print(json.dumps({"error": message}), file=sys.stderr)
    return exit_code


def main() -> int:
    db_path = os.environ.get("AGENTGUARD_DB_PATH")
    service = os.environ.get(
        "AGENTGUARD_KEYCHAIN_SERVICE", DEFAULT_SERVICE
    )
    account = os.environ.get(
        "AGENTGUARD_KEYCHAIN_ACCOUNT", DEFAULT_ACCOUNT
    )

    configured_actions = os.environ.get(
        "AGENTGUARD_ALLOWED_ACTION_IDS"
    )

    if not configured_actions:
        return emit_error("Authorization policy is missing.", 2)

    allowed_action_ids = {
        item.strip()
        for item in configured_actions.split(",")
        if item.strip()
    }

    if not allowed_action_ids:
        return emit_error("Authorization policy is empty.", 2)

    if not db_path:
        return emit_error("Database configuration is missing.", 2)

    try:
        secret_key = load_key(service=service, account=account)
    except RuntimeError:
        return emit_error(
            "Could not load signing key from Keychain.", 2
        )

    try:
        request_bytes = sys.stdin.buffer.readline(MAX_REQUEST_BYTES + 1)

        if not request_bytes:
            raise ValueError("Request is empty")

        if len(request_bytes) > MAX_REQUEST_BYTES:
            raise ValueError("Request exceeds the size limit")

        request = json.loads(request_bytes)

        if not isinstance(request, dict):
            raise ValueError("Request must be a JSON object")

        if set(request) != {"action_id"}:
            raise ValueError(
                "Request must contain only the action_id field"
            )

        action_id = request.get("action_id")

        if (
            not isinstance(action_id, str)
            or not action_id
            or action_id != action_id.strip()
            or len(action_id) > 200
        ):
            raise ValueError(
                "action_id must be a non-empty string of at most 200 characters"
            )

        if action_id not in allowed_action_ids:
            return emit_error(
                "Request is not authorized for this action.", 1
            )

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

    except json.JSONDecodeError:
        return emit_error("Request contains invalid JSON.", 1)
    except PermissionError:
        return emit_error(
            "Request is not authorized for this action.", 1
        )
    except (ValueError, TypeError, OSError) as exc:
        return emit_error(str(exc), 1)


if __name__ == "__main__":
    raise SystemExit(main())
