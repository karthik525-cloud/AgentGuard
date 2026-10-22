"""Deterministic verification of agent claims against connector evidence."""

from dataclasses import dataclass
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass(frozen=True)
class EvidenceRecord:
    """Evidence produced by a connector, not directly by an AI agent.

    This type makes the intended trust boundary explicit. It is not, by
    itself, cryptographic proof that a connector or record is trustworthy.
    """
    action_id: str
    source: str
    record_id: str
    observed_state: str


def verify_claim(
    claim: dict[str, Any],
    evidence: list[EvidenceRecord],
) -> dict[str, Any]:
    """Compare a claim with evidence records supplied by a trusted caller."""
    if not isinstance(claim, dict):
        raise ValueError("claim must be a dictionary")

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
        if isinstance(item, EvidenceRecord)
        and item.action_id == action_id
        and isinstance(item.observed_state, str)
        and item.observed_state.strip()
        and isinstance(item.source, str)
        and item.source.strip()
        and isinstance(item.record_id, str)
        and item.record_id.strip()
    ]

    used = [
        {
            "source": item.source,
            "record_id": item.record_id,
            "observed_state": item.observed_state,
        }
        for item in usable
    ]

    if not usable:
        verdict = Verdict.INCONCLUSIVE
        reason = "No connector evidence was available for this action."
    else:
        observed_states = {item.observed_state for item in usable}

        if len(observed_states) != 1:
            verdict = Verdict.INCONCLUSIVE
            reason = "Evidence conflicts about the actual outcome."
        else:
            actual_state = next(iter(observed_states))
            if actual_state == claimed_state:
                verdict = Verdict.VERIFIED
                reason = "Connector evidence supports the claimed outcome."
            else:
                verdict = Verdict.FAILED
                reason = (
                    f"The agent claimed '{claimed_state}', but evidence "
                    f"reports '{actual_state}'."
                )

    return {
        "verdict": verdict.value,
        "action_id": action_id,
        "claimed_state": claimed_state,
        "reason": reason,
        "evidence_used": used,
    }
