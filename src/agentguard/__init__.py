"""Public API for AgentGuard."""

from .core import EvidenceRecord, Verdict, verify_claim
from .agent_integration import (
    AuditEvent,
    AuditSink,
    EvidenceProvider,
    InMemoryAuditLog,
    SQLiteBookingEvidenceProvider,
    verify_agent_claim,
)
from .evidence_signing import (
    sign_evidence,
    verify_signed_evidence,
    verify_signed_claim,
    verify_and_consume_claim,
)
from .replay_store import ReplayDetectedError, SQLiteReplayStore
from .sqlite_source import (
    record_booking,
    verify_from_sqlite,
    verify_signed_from_sqlite,
)

__all__ = [
    "EvidenceRecord",
    "Verdict",
    "verify_claim",
    "AuditEvent",
    "AuditSink",
    "EvidenceProvider",
    "InMemoryAuditLog",
    "SQLiteBookingEvidenceProvider",
    "verify_agent_claim",
    "sign_evidence",
    "verify_signed_evidence",
    "verify_signed_claim",
    "verify_and_consume_claim",
    "ReplayDetectedError",
    "SQLiteReplayStore",
    "record_booking",
    "verify_from_sqlite",
    "verify_signed_from_sqlite",
]

__version__ = "0.1.0"
