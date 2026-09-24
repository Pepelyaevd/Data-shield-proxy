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

# Уровни риска пользователя (по возрастанию серьёзности). Присваиваются СИСТЕМОЙ
# автоматически по истории DLP-срабатываний (не вручную офицером).
RISK_LEVELS = ("yellow", "orange", "red", "black")

# Порядок серьёзности находок DLP (для сортировки топ-проблем).
_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def classify_level(ncrit: int, nhigh: int, nmed: int, nlow: int) -> Optional[str]:
    """Правило автоматического присвоения уровня риска пользователю.

    Вход — число DLP-находок пользователя по серьёзности за период.
    Возвращает уровень (yellow/orange/red/black) либо None для «чистого»
    пользователя (срабатываний нет). Пороги подобраны для MVP и объяснимы:

        black  — ≥2 критических (повторная/множественная утечка секретов);
        red    — ≥1 критическая ИЛИ ≥3 high;
        orange — ≥1 high ИЛИ ≥2 medium;
        yellow — есть хотя бы одна находка medium/low.
    """
    if ncrit >= 2:
        return "black"
    if ncrit >= 1 or nhigh >= 3:
        return "red"
    if nhigh >= 1 or nmed >= 2:
        return "orange"
    if nmed >= 1 or nlow >= 1:
        return "yellow"
    return None


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

    def usage_by_user(
        self, since: Optional[str] = None, until: Optional[str] = None
    ) -> List[sqlite3.Row]:
        where, params = self._period_clause(since, until)
        return self.conn.execute(
            f"""
            SELECT user,
                   COUNT(*)                                  AS requests,
                   COUNT(DISTINCT agent)                     AS agents,
                   COUNT(DISTINCT provider)                  AS providers,
                   SUM(COALESCE(tokens_in, 0))               AS tokens_in,
                   SUM(COALESCE(tokens_out, 0))              AS tokens_out,
                   SUM(CASE WHEN verdict='alert' THEN 1 ELSE 0 END) AS alerts,
                   MAX(ts)                                   AS last_seen
            FROM events
            {where}
            GROUP BY user
            ORDER BY requests DESC
            """,
            params,
        ).fetchall()

    def usage_by_agent(
        self, since: Optional[str] = None, until: Optional[str] = None
    ) -> List[sqlite3.Row]:
        where, params = self._period_clause(since, until)
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
        self,
        since: Optional[str] = None,
        until: Optional[str] = None,
        user: Optional[str] = None,
        limit: int = 500,
    ) -> List[sqlite3.Row]:
        clauses = ["verdict = 'alert'"]
        params: List[Any] = []
        if since:
            clauses.append("ts >= ?")
            params.append(since)
        if until:
            clauses.append("ts <= ?")
            params.append(until)
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

    def counts(
        self, since: Optional[str] = None, until: Optional[str] = None
    ) -> Dict[str, int]:
        where, params = self._period_clause(since, until)
        row = self.conn.execute(
            f"""
            SELECT COUNT(*) AS total,
                   SUM(CASE WHEN verdict='alert' THEN 1 ELSE 0 END) AS alerts,
                   COUNT(DISTINCT user) AS users
            FROM events
            {where}
            """,
            params,
        ).fetchone()
        return {
            "total": row["total"] or 0,
            "alerts": row["alerts"] or 0,
            "users": row["users"] or 0,
        }

    def top_problems(
        self,
        since: Optional[str] = None,
        until: Optional[str] = None,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """Агрегирует сработавшие сигнатуры alert-событий → топ проблем.

        Разбор JSON matched_signatures на стороне Python: в MVP объём alert-событий
        невелик, а хранить нормализованную таблицу находок пока избыточно.
        Группировка по (detector, category); severity берётся максимальная.
        """
        where, params = self._period_clause(since, until)
        alert_clause = ("AND verdict='alert'" if where
                        else "WHERE verdict='alert'")
        rows = self.conn.execute(
            f"""
            SELECT user, matched_signatures
            FROM events
            {where} {alert_clause}
            """,
            params,
        ).fetchall()

        agg: Dict[str, Dict[str, Any]] = {}
        for r in rows:
            try:
                sigs = json.loads(r["matched_signatures"] or "[]")
            except Exception:
                continue
            for s in sigs:
                det = s.get("detector", "?")
                cat = s.get("category", "?")
                sev = s.get("severity", "low")
                cnt = int(s.get("count", 1) or 1)
                key = f"{det}|{cat}"
                a = agg.setdefault(
                    key,
                    {
                        "detector": det,
                        "category": cat,
                        "severity": sev,
                        "hits": 0,
                        "events": 0,
                        "users": set(),
                    },
                )
                a["hits"] += cnt
                a["events"] += 1
                if r["user"]:
                    a["users"].add(r["user"])
                if _SEVERITY_ORDER.get(sev, 0) > _SEVERITY_ORDER.get(a["severity"], 0):
                    a["severity"] = sev

        out = []
        for a in agg.values():
            a["users"] = len(a["users"])
            out.append(a)
        out.sort(
            key=lambda a: (_SEVERITY_ORDER.get(a["severity"], 0), a["hits"]),
            reverse=True,
        )
        return out[:limit]

    def distinct_users(self) -> List[str]:
        rows = self.conn.execute(
            "SELECT DISTINCT user FROM events WHERE user IS NOT NULL ORDER BY user"
        ).fetchall()
        return [r["user"] for r in rows]

    # ---- уровни риска пользователей: вычисляются системой ------------------ #

    def user_risk(
        self, since: Optional[str] = None, until: Optional[str] = None
    ) -> Dict[str, Dict[str, Any]]:
        """Система вычисляет уровень риска каждого пользователя за период.

        Разбирает matched_signatures alert-событий, считает находки по серьёзности
        и применяет classify_level. Возвращает
            {user: {level, ncrit, nhigh, nmed, nlow, alerts, reason}}.
        «Чистые» пользователи (без срабатываний) в результат не попадают —
        для них уровень отсутствует (None).
        """
        where, params = self._period_clause(since, until)
        alert_clause = ("AND verdict='alert'" if where else "WHERE verdict='alert'")
        rows = self.conn.execute(
            f"SELECT user, matched_signatures FROM events {where} {alert_clause}",
            params,
        ).fetchall()

        acc: Dict[str, Dict[str, int]] = {}
        for r in rows:
            user = r["user"] or "—"
            try:
                sigs = json.loads(r["matched_signatures"] or "[]")
            except Exception:
                continue
            a = acc.setdefault(
                user, {"ncrit": 0, "nhigh": 0, "nmed": 0, "nlow": 0, "alerts": 0}
            )
            a["alerts"] += 1
            for s in sigs:
                sev = s.get("severity", "low")
                cnt = int(s.get("count", 1) or 1)
                key = {"critical": "ncrit", "high": "nhigh",
                       "medium": "nmed", "low": "nlow"}.get(sev, "nlow")
                a[key] += cnt

        out: Dict[str, Dict[str, Any]] = {}
        for user, a in acc.items():
            level = classify_level(a["ncrit"], a["nhigh"], a["nmed"], a["nlow"])
            if level is None:
                continue
            out[user] = {
                "level": level,
                "reason": self._risk_reason(a),
                **a,
            }
        return out

    @staticmethod
    def _risk_reason(a: Dict[str, int]) -> str:
        parts = []
        for label, key in (("критич.", "ncrit"), ("high", "nhigh"),
                           ("medium", "nmed"), ("low", "nlow")):
            if a.get(key):
                parts.append(f"{label}×{a[key]}")
        return ", ".join(parts) or "—"

    @staticmethod
    def _period_clause(since: Optional[str], until: Optional[str]):
        clauses: List[str] = []
        params: List[Any] = []
        if since:
            clauses.append("ts >= ?")
            params.append(since)
        if until:
            clauses.append("ts <= ?")
            params.append(until)
        if clauses:
            return "WHERE " + " AND ".join(clauses), params
        return "", []

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "EventStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
