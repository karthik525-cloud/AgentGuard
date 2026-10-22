"""Trusted connector prototype for reading and signing SQLite evidence."""

import sqlite3
from pathlib import Path
from typing import Any

from .evidence_signing import sign_evidence


def read_and_sign_booking(
    db_path: str | Path,
    action_id: str,
    secret_key: bytes,
) -> dict[str, Any] | None:
    """Read a booking from SQLite and sign its evidence.

    The key should be supplied only by trusted connector code, never by an
    untrusted AI agent. This module is not yet an isolated service.
    """
    if not isinstance(action_id, str) or not action_id.strip():
        raise ValueError("action_id must be a non-empty string")

    if not isinstance(secret_key, bytes) or len(secret_key) < 32:
        raise ValueError("secret_key must contain at least 32 bytes")

    if not Path(db_path).is_file():
        return None

    with sqlite3.connect(db_path) as connection:
        row = connection.execute(
            """
            SELECT action_id, record_id, state
            FROM bookings
            WHERE action_id = ?
            """,
            (action_id,),
        ).fetchone()

    if row is None:
        return None

    evidence = {
        "action_id": row[0],
        "record_id": row[1],
        "observed_state": row[2],
        "source": "sqlite-booking-database",
    }
    return sign_evidence(evidence, secret_key)
