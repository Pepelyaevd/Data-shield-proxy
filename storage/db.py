"""Доступ к SQLite-хранилищу событий.

Тонкий слой поверх sqlite3 (stdlib): инициализация схемы, запись события,
выборки для отчётов. Потокобезопасность обеспечивается на уровне соединения
(check_same_thread=False + короткие транзакции); addon пишет из одного потока.
"""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

_SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")

DEFAULT_DB_PATH = os.environ.get("DSP_DB_PATH", "data/events.db")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Event:
    ts: str = field(default_factory=_utcnow)
    user: Optional[str] = None
    device: Optional[str] = None
    agent: Optional[str] = None
    provider: Optional[str] = None
    model: Optional[str] = None
    destination: Optional[str] = None
    direction: str = "request"
    tokens_in: Optional[int] = None
    tokens_out: Optional[int] = None
    bytes: Optional[int] = None
    verdict: str = "allow"
    matched_signatures: List[Dict[str, Any]] = field(default_factory=list)


class EventStore:
    def __init__(self, path: str = DEFAULT_DB_PATH) -> None:
        self.path = path
        if path != ":memory:":
            parent = os.path.dirname(os.path.abspath(path))
            os.makedirs(parent, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self._init_schema()

    def _init_schema(self) -> None:
        with open(_SCHEMA_PATH, "r", encoding="utf-8") as f:
            self.conn.executescript(f.read())
        self.conn.commit()

    def record(self, event: Event) -> int:
        cur = self.conn.execute(
            """
            INSERT INTO events (
                ts, user, device, agent, provider, model, destination,
                direction, tokens_in, tokens_out, bytes, verdict, matched_signatures
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                event.ts,
                event.user,
                event.device,
                event.agent,
                event.provider,
                event.model,
                event.destination,
                event.direction,
                event.tokens_in,
                event.tokens_out,
                event.bytes,
                event.verdict,
                json.dumps(event.matched_signatures, ensure_ascii=False),
            ),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    # ---- выборки для отчётности ------------------------------------------- #

    def usage_by_user(self, since: Optional[str] = None) -> List[sqlite3.Row]:
        where, params = self._since_clause(since)
        return self.conn.execute(
            f"""
            SELECT user,
                   COUNT(*)                                  AS requests,
                   COUNT(DISTINCT agent)                     AS agents,
                   COUNT(DISTINCT provider)                  AS providers,
                   SUM(COALESCE(tokens_in, 0))               AS tokens_in,
                   SUM(COALESCE(tokens_out, 0))              AS tokens_out,
                   SUM(CASE WHEN verdict='alert' THEN 1 ELSE 0 END) AS alerts
            FROM events
            {where}
            GROUP BY user
            ORDER BY requests DESC
            """,
            params,
        ).fetchall()

    def usage_by_agent(self, since: Optional[str] = None) -> List[sqlite3.Row]:
        where, params = self._since_clause(since)
        return self.conn.execute(
            f"""
            SELECT agent, provider,
                   COUNT(*)                                  AS requests,
                   COUNT(DISTINCT user)                      AS users,
                   SUM(CASE WHEN verdict='alert' THEN 1 ELSE 0 END) AS alerts
            FROM events
            {where}
            GROUP BY agent, provider
            ORDER BY requests DESC
            """,
            params,
        ).fetchall()

    def incidents(
        self, since: Optional[str] = None, user: Optional[str] = None, limit: int = 500
    ) -> List[sqlite3.Row]:
        clauses = ["verdict = 'alert'"]
        params: List[Any] = []
        if since:
            clauses.append("ts >= ?")
            params.append(since)
        if user:
            clauses.append("user = ?")
            params.append(user)
        where = "WHERE " + " AND ".join(clauses)
        params.append(limit)
        return self.conn.execute(
            f"""
            SELECT id, ts, user, agent, provider, model, destination,
                   direction, verdict, matched_signatures
            FROM events
            {where}
            ORDER BY ts DESC
            LIMIT ?
            """,
            params,
        ).fetchall()

    def counts(self) -> Dict[str, int]:
        row = self.conn.execute(
            """
            SELECT COUNT(*) AS total,
                   SUM(CASE WHEN verdict='alert' THEN 1 ELSE 0 END) AS alerts
            FROM events
            """
        ).fetchone()
        return {"total": row["total"] or 0, "alerts": row["alerts"] or 0}

    @staticmethod
    def _since_clause(since: Optional[str]):
        if since:
            return "WHERE ts >= ?", [since]
        return "", []

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "EventStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
