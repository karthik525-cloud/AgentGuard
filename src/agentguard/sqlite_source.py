"""SQLite-backed independent evidence source for AgentGuard demos."""

import sqlite3
from pathlib import Path
from typing import Any

from .core import verify_claim


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
    if not all(isinstance(value, str) and value.strip()
               for value in (action_id, record_id, state)):
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
    """Read the application's record, then independently evaluate the claim."""
    action_id = claim.get("action_id")
    if not isinstance(action_id, str) or not action_id.strip():
        raise ValueError("claim requires a non-empty action_id")

    if not Path(db_path).is_file():
        evidence = []
    else:
        with sqlite3.connect(db_path) as connection:
            row = connection.execute(
                """
                SELECT action_id, record_id, state
                FROM bookings
                WHERE action_id = ?
                """,
                (action_id,),
            ).fetchone()

        evidence = []
        if row:
            evidence.append({
                "action_id": row[0],
                "record_id": row[1],
                "observed_state": row[2],
                "source": "sqlite-booking-database",
                "independent": True,
                "trusted": True,
            })

    return verify_claim(claim, evidence)
