"""Deterministic verification of agent claims against independent evidence."""

from enum import Enum
from typing import Any


class Verdict(str, Enum):
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"


def verify_claim(
    claim: dict[str, Any],
    evidence: list[dict[str, Any]],
) -> dict[str, Any]:
    """Verify a claim using trusted, independent evidence for the same action.

    Evidence trust flags must be assigned by a trusted integration, never
    accepted directly from an AI agent's own narrative.
    """
    action_id = claim.get("action_id")
    claimed_state = claim.get("claimed_state")

    if not isinstance(action_id, str) or not action_id.strip():
        raise ValueError("claim requires a non-empty action_id")
    if not isinstance(claimed_state, str) or not claimed_state.strip():
        raise ValueError("claim requires a non-empty claimed_state")
    if not isinstance(evidence, list):
        raise ValueError("evidence must be a list")

    usable = [
        item for item in evidence
        if isinstance(item, dict)
        and item.get("action_id") == action_id
        and item.get("independent") is True
        and item.get("trusted") is True
        and isinstance(item.get("observed_state"), str)
        and item.get("observed_state", "").strip()
        and isinstance(item.get("source"), str)
        and item.get("source", "").strip()
        and isinstance(item.get("record_id"), str)
        and item.get("record_id", "").strip()
    ]

    used = [
        {
            "source": item["source"],
            "record_id": item["record_id"],
            "observed_state": item["observed_state"],
        }
        for item in usable
    ]

    if not usable:
        verdict = Verdict.INCONCLUSIVE
        reason = "No trusted independent evidence was available for this action."

    else:
        observed_states = {item["observed_state"] for item in usable}

        if len(observed_states) != 1:
            verdict = Verdict.INCONCLUSIVE
            reason = "Trusted evidence conflicts about the actual outcome."
        else:
            actual_state = next(iter(observed_states))
            if actual_state == claimed_state:
                verdict = Verdict.VERIFIED
                reason = "Trusted independent evidence supports the claimed outcome."
            else:
                verdict = Verdict.FAILED
                reason = (
                    f"The agent claimed '{claimed_state}', but trusted evidence "
                    f"reports '{actual_state}'."
                )

    return {
        "verdict": verdict.value,
        "action_id": action_id,
        "claimed_state": claimed_state,
        "reason": reason,
        "evidence_used": used,
    }
