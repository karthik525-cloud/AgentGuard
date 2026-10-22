"""Public API for AgentGuard."""

from .core import EvidenceRecord, Verdict, verify_claim
from .evidence_signing import (
    sign_evidence,
    verify_signed_evidence,
    verify_signed_claim,
)
from .sqlite_source import (
    record_booking,
    verify_from_sqlite,
    verify_signed_from_sqlite,
)

__all__ = [
    "EvidenceRecord",
    "Verdict",
    "verify_claim",
    "sign_evidence",
    "verify_signed_evidence",
    "verify_signed_claim",
    "record_booking",
    "verify_from_sqlite",
    "verify_signed_from_sqlite",
]

__version__ = "0.1.0"
