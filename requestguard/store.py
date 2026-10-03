"""SQLite persistence for bans and AbuseIPDB cache."""

from __future__ import annotations

import os
import sqlite3
import threading
from dataclasses import dataclass


@dataclass(frozen=True)
class Ban:
    ip: str
    reason: str
    detail: str
    created_at: int
    expires_at: int
    intensity: float | None


@dataclass(frozen=True)
class Reputation:
    ip: str
    score: int
    checked_at: int
    expires_at: int
    detail: str
    country: str = ""


def _ts(now: float) -> int:
    return int(now)


class Store:
    def __init__(self, path: str) -> None:
        if path != ":memory:":
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=3000")
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS bans (
                ip TEXT PRIMARY KEY,
                reason TEXT NOT NULL,
                detail TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                intensity REAL
            );
            CREATE TABLE IF NOT EXISTS reputation (
                ip TEXT PRIMARY KEY,
                score INTEGER NOT NULL,
                checked_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                detail TEXT NOT NULL,
                country TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_bans_expires ON bans(expires_at);
            CREATE INDEX IF NOT EXISTS idx_reputation_expires ON reputation(expires_at);
            """
        )
        columns = {row["name"] for row in self._conn.execute("PRAGMA table_info(reputation)")}
        if "country" not in columns:
            self._conn.execute("ALTER TABLE reputation ADD COLUMN country TEXT NOT NULL DEFAULT ''")
        self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def ban(
        self,
        ip: str,
        reason: str,
        days: int,
        now: float,
        detail: str = "",
        intensity: float | None = None,
        expires_at: int | None = None,
    ) -> tuple[Ban, bool]:
        """Store a ban. A longer existing ban is left in place."""
        now_ts = _ts(now)
        new_expires = now_ts + days * 86400 if expires_at is None else int(expires_at)
        detail = detail[:200]
        with self._lock:
            row = self._conn.execute("SELECT * FROM bans WHERE ip = ?", (ip,)).fetchone()
            active = row is not None and int(row["expires_at"]) > now_ts
            if active and int(row["expires_at"]) >= new_expires:
                return _ban_from_row(row), False
            created = int(row["created_at"]) if active else now_ts
            self._conn.execute(
                """
                INSERT INTO bans (ip, reason, detail, created_at, expires_at, intensity)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    reason = excluded.reason,
                    detail = excluded.detail,
                    created_at = excluded.created_at,
                    expires_at = excluded.expires_at,
                    intensity = excluded.intensity
                """,
                (ip, reason, detail, created, new_expires, intensity),
            )
            self._conn.commit()
            saved = self._conn.execute("SELECT * FROM bans WHERE ip = ?", (ip,)).fetchone()
        return _ban_from_row(saved), True

    def get_ban(self, ip: str, now: float) -> Ban | None:
        now_ts = _ts(now)
        with self._lock:
            row = self._conn.execute("SELECT * FROM bans WHERE ip = ?", (ip,)).fetchone()
            if row is None:
                return None
            if int(row["expires_at"]) <= now_ts:
                self._conn.execute("DELETE FROM bans WHERE ip = ?", (ip,))
                self._conn.commit()
                return None
            return _ban_from_row(row)

    def list_bans(self, now: float) -> list[Ban]:
        now_ts = _ts(now)
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM bans WHERE expires_at > ? ORDER BY expires_at DESC",
                (now_ts,),
            ).fetchall()
        return [_ban_from_row(row) for row in rows]

    def save_reputation(
        self,
        ip: str,
        score: int,
        now: float,
        days: int,
        detail: str = "",
        country: str = "",
    ) -> Reputation:
        now_ts = _ts(now)
        expires = now_ts + days * 86400
        country = country[:8]
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO reputation (ip, score, checked_at, expires_at, detail, country)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    score = excluded.score,
                    checked_at = excluded.checked_at,
                    expires_at = excluded.expires_at,
                    detail = excluded.detail,
                    country = excluded.country
                """,
                (ip, score, now_ts, expires, detail[:200], country),
            )
            self._conn.commit()
        return Reputation(ip, score, now_ts, expires, detail[:200], country)

    def get_reputation(self, ip: str, now: float) -> Reputation | None:
        now_ts = _ts(now)
        with self._lock:
            row = self._conn.execute("SELECT * FROM reputation WHERE ip = ?", (ip,)).fetchone()
            if row is None:
                return None
            if int(row["expires_at"]) <= now_ts:
                self._conn.execute("DELETE FROM reputation WHERE ip = ?", (ip,))
                self._conn.commit()
                return None
            return _reputation_from_row(row)

    def list_reputation(self, now: float) -> list[Reputation]:
        now_ts = _ts(now)
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM reputation WHERE expires_at > ? ORDER BY checked_at DESC",
                (now_ts,),
            ).fetchall()
        return [_reputation_from_row(row) for row in rows]

    def purge(self, now: float) -> int:
        now_ts = _ts(now)
        with self._lock:
            banned = self._conn.execute("DELETE FROM bans WHERE expires_at <= ?", (now_ts,))
            scored = self._conn.execute("DELETE FROM reputation WHERE expires_at <= ?", (now_ts,))
            self._conn.commit()
            return int(banned.rowcount) + int(scored.rowcount)


def _reputation_from_row(row: sqlite3.Row) -> Reputation:
    return Reputation(
        ip=row["ip"],
        score=int(row["score"]),
        checked_at=int(row["checked_at"]),
        expires_at=int(row["expires_at"]),
        detail=row["detail"],
        country=row["country"] or "",
    )


def _ban_from_row(row: sqlite3.Row) -> Ban:
    intensity = row["intensity"]
    return Ban(
        ip=row["ip"],
        reason=row["reason"],
        detail=row["detail"],
        created_at=int(row["created_at"]),
        expires_at=int(row["expires_at"]),
        intensity=None if intensity is None else float(intensity),
    )
