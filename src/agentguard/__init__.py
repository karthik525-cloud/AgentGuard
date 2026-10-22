"""Public API for AgentGuard."""

from .core import Verdict, verify_claim
from .sqlite_source import record_booking, verify_from_sqlite

__all__ = [
    "Verdict",
    "verify_claim",
    "record_booking",
    "verify_from_sqlite",
]

__version__ = "0.1.0"
