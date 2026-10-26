
"""HMAC signing and freshness validation for AgentGuard evidence."""

import hashlib
import hmac
import json
import math
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from .replay_store import ReplayDetectedError, SQLiteReplayStore


def _validate_secret_key(secret_key: bytes) -> None:
    if not isinstance(secret_key, bytes) or len(secret_key) < 32:
        raise ValueError("secret_key must contain at least 32 bytes")


def _validate_duration(value: object, name: str) -> None:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(value)
        or value < 0
    ):
        raise ValueError(f"{name} cannot be negative or non-finite")


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sign_evidence(
    evidence: dict[str, Any],
    secret_key: bytes,
) -> dict[str, Any]:
    _validate_secret_key(secret_key)
    if not isinstance(evidence, dict):
        raise ValueError("evidence must be a dictionary")

    payload = dict(evidence)
    payload.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    payload["evidence_id"] = str(uuid.uuid4())

    signature = hmac.new(
        secret_key, _canonical_bytes(payload), hashlib.sha256
    ).hexdigest()
    return {"evidence": payload, "signature": signature}


def verify_signed_evidence(
    envelope: dict[str, Any],
    secret_key: bytes,
) -> bool:
    _validate_secret_key(secret_key)
    if not isinstance(envelope, dict):
        return False

    payload = envelope.get("evidence")
    signature = envelope.get("signature")
    if not isinstance(payload, dict) or not isinstance(signature, str):
        return False

    try:
        expected = hmac.new(
            secret_key, _canonical_bytes(payload), hashlib.sha256
        ).hexdigest()
    except (OverflowError, RecursionError, TypeError, ValueError, UnicodeError):
        return False
    return hmac.compare_digest(expected, signature)


def is_evidence_fresh(
    envelope: dict[str, Any],
    secret_key: bytes,
    *,
    max_age_seconds: int = 300,
    clock_skew_seconds: int = 30,
) -> bool:
    _validate_duration(max_age_seconds, "max_age_seconds")
    _validate_duration(clock_skew_seconds, "clock_skew_seconds")
    if not verify_signed_evidence(envelope, secret_key):
        return False

    timestamp = envelope["evidence"].get("timestamp")
    if not isinstance(timestamp, str):
        return False

    try:
        parsed = datetime.fromisoformat(timestamp)
        if parsed.tzinfo is None:
            return False
        age = time.time() - parsed.timestamp()
    except (ValueError, OverflowError, OSError):
        return False

    return -clock_skew_seconds <= age <= max_age_seconds


def _is_valid_evidence_id(evidence_id: object) -> bool:
    if not isinstance(evidence_id, str):
        return False

    try:
        parsed = uuid.UUID(evidence_id)
    except ValueError:
        return False

    return parsed.version == 4 and str(parsed) == evidence_id


def verify_signed_claim(
    claim: dict[str, Any],
    envelopes: list[dict[str, Any]],
    secret_key: bytes,
) -> dict[str, Any]:
    """Use only correctly signed, fresh evidence to evaluate a claim."""
    from .core import EvidenceRecord, verify_claim

    _validate_secret_key(secret_key)
    if not isinstance(envelopes, list):
        raise ValueError("envelopes must be a list")

    evidence_records = []
    for envelope in envelopes:
        if not is_evidence_fresh(envelope, secret_key):
            continue

        payload = envelope["evidence"]
        try:
            record = EvidenceRecord(
                action_id=payload["action_id"],
                source=payload["source"],
                record_id=payload["record_id"],
                observed_state=payload["observed_state"],
            )
        except (KeyError, TypeError):
            continue

        evidence_records.append(record)

    return verify_claim(claim, evidence_records)


def verify_and_consume_claim(
    claim: dict[str, Any],
    envelope: dict[str, Any],
    secret_key: bytes,
    replay_store: SQLiteReplayStore,
    *,
    expected_action_id: str,
) -> dict[str, Any]:
    """Verify one envelope and atomically consume it after verification.

    Unlike ``verify_signed_claim``, this operation is for one-time workflows.
    Read-only verification remains repeatable.

    ``expected_action_id`` must come from the trusted protected-operation
    context, never from an untrusted agent request.
    """
    if not isinstance(expected_action_id, str) or not expected_action_id.strip():
        raise ValueError("expected_action_id must be a non-empty string")
    if not isinstance(claim, dict):
        raise ValueError("claim must be a dictionary")
    if claim.get("action_id") != expected_action_id:
        raise ValueError("claim action_id does not match expected_action_id")
    if not isinstance(replay_store, SQLiteReplayStore):
        raise ValueError("replay_store must be a SQLiteReplayStore")
    if not is_evidence_fresh(envelope, secret_key):
        raise ValueError("evidence must have a valid signature and be fresh")

    payload = envelope["evidence"]
    evidence_id = payload.get("evidence_id")
    if not _is_valid_evidence_id(evidence_id):
        raise ValueError("evidence requires a canonical UUID4 evidence_id")
    if payload.get("action_id") != expected_action_id:
        raise ValueError("evidence action_id does not match expected_action_id")

    result = verify_signed_claim(claim, [envelope], secret_key)
    if result["verdict"] != "VERIFIED":
        return result

    if not replay_store.consume(evidence_id, expected_action_id):
        raise ReplayDetectedError("evidence has already been consumed")

    return result
