"""SQLite-backed evidence source for AgentGuard demos."""

import sqlite3
from pathlib import Path
from typing import Any

from .core import EvidenceRecord, verify_claim


def initialize_database(db_path: str | Path) -> None:
    """Create the controlled application's booking table."""
    with sqlite3.connect(db_path) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS bookings (
                action_id TEXT PRIMARY KEY,
                record_id TEXT NOT NULL UNIQUE,
                state TEXT NOT NULL
            )
        """)


def record_booking(
    db_path: str | Path,
    action_id: str,
    record_id: str,
    state: str,
) -> None:
    """Write the state held by the controlled booking application."""
    if not all(
        isinstance(value, str) and value.strip()
        for value in (action_id, record_id, state)
    ):
        raise ValueError("action_id, record_id and state must be non-empty")

    initialize_database(db_path)
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            INSERT INTO bookings (action_id, record_id, state)
            VALUES (?, ?, ?)
            ON CONFLICT(action_id) DO UPDATE SET
                record_id = excluded.record_id,
                state = excluded.state
            """,
            (action_id, record_id, state),
        )


def verify_from_sqlite(
    claim: dict[str, Any],
    db_path: str | Path,
) -> dict[str, Any]:
    """Read a booking record and verify the claim against it."""
    action_id = claim.get("action_id")
    if not isinstance(action_id, str) or not action_id.strip():
        raise ValueError("claim requires a non-empty action_id")

    evidence: list[EvidenceRecord] = []

    if Path(db_path).is_file():
        with sqlite3.connect(db_path) as connection:
            row = connection.execute(
                """
                SELECT action_id, record_id, state
                FROM bookings
                WHERE action_id = ?
                """,
                (action_id,),
            ).fetchone()

        if row:
            evidence.append(
                EvidenceRecord(
                    action_id=row[0],
                    record_id=row[1],
                    observed_state=row[2],
                    source="sqlite-booking-database",
                )
            )

    return verify_claim(claim, evidence)


def verify_signed_from_sqlite(
    claim: dict[str, Any],
    db_path: str | Path,
    secret_key: bytes,
) -> dict[str, Any]:
    """Verify a claim using signed evidence read from SQLite."""
    from .evidence_signing import sign_evidence, verify_signed_claim

    action_id = claim.get("action_id")
    if not isinstance(action_id, str) or not action_id.strip():
        raise ValueError("claim requires a non-empty action_id")

    evidence_envelopes = []

    if Path(db_path).is_file():
        with sqlite3.connect(db_path) as connection:
            row = connection.execute(
                """
                SELECT action_id, record_id, state
                FROM bookings
                WHERE action_id = ?
                """,
                (action_id,),
            ).fetchone()

        if row:
            evidence = {
                "action_id": row[0],
                "record_id": row[1],
                "observed_state": row[2],
                "source": "sqlite-booking-database",
            }
            evidence_envelopes.append(sign_evidence(evidence, secret_key))

    return verify_signed_claim(claim, evidence_envelopes, secret_key)
