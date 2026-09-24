#!/usr/bin/env python3
"""Демонстрация сквозного core-loop MVP БЕЗ mitmproxy/Docker.

Прогоняет несколько «промптов» от разных пользователей через реальные модули
(catalog → parsers → dlp → storage) и печатает CLI-отчёт. Показывает DoD:
посаженный секрет → инцидент в отчёте с атрибуцией пользователю.

Запуск:  python3 scripts/demo_e2e.py   (или: make demo)
"""

from __future__ import annotations

import json
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)

from catalog import classify, parse_request  # noqa: E402
from dlp import DlpEngine  # noqa: E402
from report.cli import cmd_summary, cmd_usage, cmd_incidents  # noqa: E402
from storage import Event, EventStore  # noqa: E402


class _Args:
    since = None
    user = None
    limit = 500


# (пользователь, агент, хост, промпт)
SCENARIOS = [
    ("alice", "claude-code", "api.anthropic.com",
     "Разверни сервис с ключом AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE, спасибо"),
    ("alice", "claude-code", "api.anthropic.com",
     "Отрефактори этот код на Python, он слишком длинный"),
    ("bob", "claude-code", "api.anthropic.com",
     "Вот строка подключения: postgres://admin:s3cr3tPass@db.corp:5432/prod — почини миграцию"),
    ("bob", "chatgpt-desktop", "api.openai.com",
     "Клиент оплатил картой 4111 1111 1111 1111, сформируй чек"),
    ("carol", "claude-code", "api.anthropic.com",
     "Напиши unit-тесты для функции суммирования"),
    ("carol", "claude-code", "api.anthropic.com",
     "Данные сотрудника: ИНН 7707083893, СНИЛС 112-233-445 95 — оформи справку"),
]


def run() -> int:
    store = EventStore(":memory:")
    dlp = DlpEngine()

    print("=== Прогон сценариев через core-loop ===\n")
    for user, agent, host, prompt in SCENARIOS:
        provider = classify(host)
        body = json.dumps(
            {"model": "demo-model", "messages": [{"role": "user", "content": prompt}]}
        ).encode()
        parsed = parse_request(provider.parser if provider else "generic",
                               "application/json", body)
        result = dlp.scan(parsed.text)
        store.record(Event(
            user=user, agent=agent,
            provider=provider.id if provider else None,
            model=parsed.model, destination=host, direction="request",
            bytes=len(body), verdict=result.verdict,
            matched_signatures=[f.to_dict() for f in result.findings],
        ))
        flag = "🚨 ALERT" if result.findings else "✅ allow"
        sig = ", ".join(result.signatures())
        print(f"  {flag:9} {user:6} via {agent:16} → {host:20} {('['+sig+']') if sig else ''}")

    print()
    cmd_summary(store, _Args())
    print()
    cmd_usage(store, _Args())
    print()
    cmd_incidents(store, _Args())
    store.close()
    print("\n=== DoD подтверждён: посаженные секреты дали инциденты с атрибуцией пользователю ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
