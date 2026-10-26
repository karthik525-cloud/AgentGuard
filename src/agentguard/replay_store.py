"""Durable, atomic replay protection for one-time evidence use."""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path


class ReplayDetectedError(RuntimeError):
    """Raised when a one-time evidence identifier has already been used."""


class SQLiteReplayStore:
    """Persist consumed evidence IDs with SQLite's unique-key atomicity."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        with sqlite3.connect(self.db_path) as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS consumed_evidence (
                    evidence_id TEXT PRIMARY KEY,
                    action_id TEXT NOT NULL,
                    consumed_at TEXT NOT NULL
                )
            """)

    def consume(self, evidence_id: str, action_id: str) -> bool:
        """Record an ID once, returning False when it was already consumed."""
        connection = sqlite3.connect(
            self.db_path,
            timeout=5,
            isolation_level=None,
        )
        try:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    """
                    INSERT INTO consumed_evidence (
                        evidence_id, action_id, consumed_at
                    ) VALUES (?, ?, ?)
                    """,
                    (
                        evidence_id,
                        action_id,
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
            except sqlite3.IntegrityError:
                connection.rollback()
                return False
            connection.commit()
            return True
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def is_consumed(self, evidence_id: str) -> bool:
        """Return whether an ID is recorded as consumed."""
        with sqlite3.connect(self.db_path) as connection:
            row = connection.execute(
                "SELECT 1 FROM consumed_evidence WHERE evidence_id = ?",
                (evidence_id,),
            ).fetchone()
        return row is not None
