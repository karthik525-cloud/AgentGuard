"""Framework-agnostic verification adapter for tool-using agents."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol
import uuid

from .core import EvidenceRecord, Verdict, verify_claim
from .sqlite_source import get_booking_evidence


@dataclass(frozen=True)
class AuditEvent:
    """A safe, structured record of a verification decision or failure."""

    event_id: str
    timestamp: str
    event_type: str
    action_id: str | None
    verdict: str | None
    reason_code: str


class AuditSink(Protocol):
    """Destination for audit events; implementations must not contain secrets."""

    def emit(self, event: AuditEvent) -> None:
        """Store or forward an audit event."""


@dataclass
class InMemoryAuditLog:
    """Test/demo audit sink; it intentionally provides no tamper resistance."""

    events: list[AuditEvent] = field(default_factory=list)

    def emit(self, event: AuditEvent) -> None:
        self.events.append(event)


class EvidenceProvider(Protocol):
    """Trusted adapter that obtains evidence independently of an agent claim."""

    def collect_evidence(self, action_id: str) -> EvidenceRecord | None:
        """Collect evidence for an action using a controlled integration."""


@dataclass(frozen=True)
class SQLiteBookingEvidenceProvider:
    """Evidence provider for the local demonstration booking database."""

    db_path: Path

    def collect_evidence(self, action_id: str) -> EvidenceRecord | None:
        return get_booking_evidence(self.db_path, action_id)


def _emit(
    audit_sink: AuditSink | None,
    *,
    event_type: str,
    action_id: str | None,
    verdict: str | None,
    reason_code: str,
) -> None:
    """Emit metadata only; audit failures must not affect security decisions."""
    if audit_sink is None:
        return
    event = AuditEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        event_type=event_type,
        action_id=action_id,
        verdict=verdict,
        reason_code=reason_code,
    )
    try:
        audit_sink.emit(event)
    except Exception:
        pass


def _reason_code(result: dict[str, Any]) -> str:
    verdict = result["verdict"]
    if verdict == Verdict.VERIFIED.value:
        return "claim_verified"
    if verdict == Verdict.FAILED.value:
        return "claim_contradicted"
    if not result["evidence_used"]:
        return "evidence_missing"
    return "evidence_conflicting"


def verify_agent_claim(
    claim: dict[str, Any],
    evidence_provider: EvidenceProvider,
    *,
    audit_sink: AuditSink | None = None,
) -> dict[str, Any]:
    """Verify an agent's claim using independently collected evidence.

    The provider, not the agent, controls evidence collection. A provider
    failure produces an inconclusive verdict and a safe audit event.
    """
    try:
        preliminary = verify_claim(claim, [])
    except ValueError:
        _emit(
            audit_sink,
            event_type="verification_failure",
            action_id=None,
            verdict=Verdict.INCONCLUSIVE.value,
            reason_code="invalid_claim",
        )
        raise

    action_id = preliminary["action_id"]
    _emit(
        audit_sink,
        event_type="agent_claim_received",
        action_id=action_id,
        verdict=None,
        reason_code="claim_received",
    )
    try:
        evidence = evidence_provider.collect_evidence(action_id)
    except Exception:
        _emit(
            audit_sink,
            event_type="verification_failure",
            action_id=action_id,
            verdict=Verdict.INCONCLUSIVE.value,
            reason_code="evidence_collection_failed",
        )
        result = preliminary
    else:
        result = verify_claim(claim, [evidence] if evidence is not None else [])

    _emit(
        audit_sink,
        event_type="verification_decision",
        action_id=action_id,
        verdict=result["verdict"],
        reason_code=_reason_code(result),
    )
    return result
