"""SQLite-backed state for the reference agent.

Tracks two pieces of state across restarts:

  registration:  the agent's RA registration (agent_id, current version,
                 capabilitiesHash). Written when the agent first registers,
                 read on every Trust Card serve so the served body matches
                 what the RA sealed.

  receipt:       the latest SCITT receipt fetched from the TL. Written by
                 the staple-refresh loop, read on every Trust Card serve so
                 the embedded receipt is fresh.

The schema is intentionally minimal. Production agents that need more state
(conversation history, encounter logs, request audit) build that on top of
their own database; ANS itself does not require it.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


_SCHEMA = """
CREATE TABLE IF NOT EXISTS registration (
    agent_host           TEXT NOT NULL,
    anchor_type          TEXT NOT NULL DEFAULT 'fqdn',
    agent_id             TEXT NOT NULL UNIQUE,
    version              TEXT NOT NULL,
    capabilities_hash    TEXT,
    registered_at        TEXT NOT NULL,
    PRIMARY KEY (agent_host, anchor_type)
);

CREATE TABLE IF NOT EXISTS receipt (
    agent_id             TEXT PRIMARY KEY,
    cose_sign1_b64       TEXT NOT NULL,
    fetched_at           TEXT NOT NULL,
    FOREIGN KEY(agent_id) REFERENCES registration(agent_id)
);
"""


@dataclass(frozen=True)
class Registration:
    agent_host: str
    agent_id: str
    version: str
    capabilities_hash: str | None
    registered_at: str
    # Anchor profile that produced this registration. The lookup key
    # is (agent_host, anchor_type), so the same FQDN can carry one row
    # per anchor (FQDN + LEI + did:web for the same operator without
    # rows colliding). Defaults to "fqdn" so older serialized values
    # without this field still round-trip through the dataclass.
    anchor_type: str = "fqdn"


@dataclass(frozen=True)
class Receipt:
    agent_id: str
    cose_sign1_b64: str
    fetched_at: str


class State:
    """Thin wrapper around the SQLite file. One instance per process."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self._db_path)
        try:
            conn.execute("PRAGMA foreign_keys = ON")
            yield conn
            conn.commit()
        finally:
            conn.close()

    def upsert_registration(self, reg: Registration) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO registration (
                    agent_host, anchor_type, agent_id, version,
                    capabilities_hash, registered_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(agent_host, anchor_type) DO UPDATE SET
                    agent_id = excluded.agent_id,
                    version = excluded.version,
                    capabilities_hash = excluded.capabilities_hash,
                    registered_at = excluded.registered_at
                """,
                (
                    reg.agent_host,
                    reg.anchor_type,
                    reg.agent_id,
                    reg.version,
                    reg.capabilities_hash,
                    reg.registered_at,
                ),
            )

    def get_registration(
        self, agent_host: str, anchor_type: str = "fqdn",
    ) -> Registration | None:
        """Look up the registration for (agent_host, anchor_type).

        Defaults to fqdn for backward compatibility with the pre-anchor
        call sites that pass only the host. Callers running a non-FQDN
        registration MUST pass the matching anchor_type so the right
        row comes back.
        """
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT agent_host, agent_id, version, capabilities_hash, registered_at, anchor_type
                FROM registration
                WHERE agent_host = ? AND anchor_type = ?
                """,
                (agent_host, anchor_type),
            ).fetchone()
        if row is None:
            return None
        # Order in the SELECT matches the dataclass constructor order
        # (agent_host, agent_id, version, capabilities_hash, registered_at)
        # plus the trailing anchor_type field.
        return Registration(
            agent_host=row[0],
            agent_id=row[1],
            version=row[2],
            capabilities_hash=row[3],
            registered_at=row[4],
            anchor_type=row[5],
        )

    def upsert_receipt(self, receipt: Receipt) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO receipt (agent_id, cose_sign1_b64, fetched_at)
                VALUES (?, ?, ?)
                ON CONFLICT(agent_id) DO UPDATE SET
                    cose_sign1_b64 = excluded.cose_sign1_b64,
                    fetched_at = excluded.fetched_at
                """,
                (receipt.agent_id, receipt.cose_sign1_b64, receipt.fetched_at),
            )

    def get_receipt(self, agent_id: str) -> Receipt | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT agent_id, cose_sign1_b64, fetched_at FROM receipt WHERE agent_id = ?",
                (agent_id,),
            ).fetchone()
        if row is None:
            return None
        return Receipt(*row)
