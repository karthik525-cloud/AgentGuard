"""HMAC integrity checks for connector evidence envelopes.

Prototype only: the signing key must be kept secret and controlled by the
trusted connector. This does not prove that the original source data is true.
"""

import hashlib
import hmac
import json
from typing import Any


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    """Serialize evidence consistently before signing or verifying."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sign_evidence(
    evidence: dict[str, Any],
    secret_key: bytes,
) -> dict[str, Any]:
    """Return an evidence envelope with an HMAC-SHA256 signature."""
    if not isinstance(secret_key, bytes) or len(secret_key) < 32:
        raise ValueError("secret_key must contain at least 32 bytes")
    if not isinstance(evidence, dict):
        raise ValueError("evidence must be a dictionary")

    payload = dict(evidence)
    signature = hmac.new(
        secret_key,
        _canonical_bytes(payload),
        hashlib.sha256,
    ).hexdigest()

    return {"evidence": payload, "signature": signature}


def verify_signed_evidence(
    envelope: dict[str, Any],
    secret_key: bytes,
) -> bool:
    """Check whether the envelope signature matches its evidence payload."""
    if not isinstance(secret_key, bytes) or len(secret_key) < 32:
        raise ValueError("secret_key must contain at least 32 bytes")
    if not isinstance(envelope, dict):
        return False

    payload = envelope.get("evidence")
    signature = envelope.get("signature")
    if not isinstance(payload, dict) or not isinstance(signature, str):
        return False

    expected = hmac.new(
        secret_key,
        _canonical_bytes(payload),
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected, signature)


def verify_signed_claim(
    claim: dict[str, Any],
    envelopes: list[dict[str, Any]],
    secret_key: bytes,
) -> dict[str, Any]:
    """Verify signed evidence before using it to evaluate a claim."""
    from .core import EvidenceRecord, verify_claim

    evidence_records = []

    for envelope in envelopes:
        if not verify_signed_evidence(envelope, secret_key):
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
