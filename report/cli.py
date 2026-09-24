#!/usr/bin/env python3
"""CLI-отчётность Data-Shield-Proxy.

Команды:
    usage      — частота использования по пользователям (и агентам);
    incidents  — список DLP-инцидентов (alert-события) с сигнатурами;
    summary    — краткая сводка;
    html       — сгенерировать read-only HTML-страницу отчёта.

Примеры:
    python3 -m report.cli summary
    python3 -m report.cli usage --since 2026-09-01
    python3 -m report.cli incidents --user alice
    python3 -m report.cli html --out report_out/report.html
"""

from __future__ import annotations

import argparse
import json
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from storage import EventStore  # noqa: E402
from storage.db import DEFAULT_DB_PATH  # noqa: E402


def _fmt_signatures(raw: str) -> str:
    try:
        sigs = json.loads(raw)
    except Exception:
        return raw
    parts = []
    for s in sigs:
        tag = f"{s.get('detector')}({s.get('severity')})"
        cnt = s.get("count", 1)
        if cnt and cnt > 1:
            tag += f"x{cnt}"
        parts.append(tag)
    return ", ".join(parts)


def cmd_usage(store: EventStore, args) -> int:
    rows = store.usage_by_user(since=args.since)
    if not rows:
        print("Нет данных за выбранный период.")
        return 0
    print("Частота использования по пользователям"
          + (f" (с {args.since})" if args.since else "") + ":\n")
    header = f"{'user':<20}{'requests':>10}{'agents':>8}{'prov':>6}{'tok_in':>10}{'tok_out':>10}{'alerts':>8}"
    print(header)
    print("-" * len(header))
    for r in rows:
        print(f"{(r['user'] or '—'):<20}{r['requests']:>10}{r['agents']:>8}"
              f"{r['providers']:>6}{r['tokens_in']:>10}{r['tokens_out']:>10}{r['alerts']:>8}")

    print("\nПо агентам:\n")
    header2 = f"{'agent':<22}{'provider':<14}{'requests':>10}{'users':>7}{'alerts':>8}"
    print(header2)
    print("-" * len(header2))
    for r in store.usage_by_agent(since=args.since):
        print(f"{(r['agent'] or '—'):<22}{(r['provider'] or '—'):<14}"
              f"{r['requests']:>10}{r['users']:>7}{r['alerts']:>8}")
    return 0


def cmd_incidents(store: EventStore, args) -> int:
    rows = store.incidents(since=args.since, user=args.user, limit=args.limit)
    if not rows:
        print("Инцидентов не найдено.")
        return 0
    print(f"DLP-инциденты ({len(rows)}):\n")
    for r in rows:
        print(f"#{r['id']}  {r['ts']}  user={r['user'] or '—'}  "
              f"agent={r['agent'] or '—'}  provider={r['provider'] or '—'}  "
              f"dest={r['destination'] or '—'}")
        print(f"     сигнатуры: {_fmt_signatures(r['matched_signatures'])}")
    return 0


def cmd_summary(store: EventStore, args) -> int:
    c = store.counts()
    users = store.usage_by_user()
    print("Сводка Data-Shield-Proxy")
    print("========================")
    print(f"Всего событий : {c['total']}")
    print(f"DLP-алертов   : {c['alerts']}")
    print(f"Пользователей : {len(users)}")
    if users:
        top = users[0]
        print(f"Топ по частоте: {top['user']} ({top['requests']} запросов, {top['alerts']} алертов)")
    return 0


def cmd_html(store: EventStore, args) -> int:
    from report.html import render_html

    html = render_html(store, since=args.since)
    out = args.out
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"HTML-отчёт записан: {out}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Отчётность Data-Shield-Proxy")
    parser.add_argument("--db", default=DEFAULT_DB_PATH, help=f"путь к БД (по умолчанию {DEFAULT_DB_PATH})")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_usage = sub.add_parser("usage", help="частота использования")
    p_usage.add_argument("--since", default=None, help="ISO-дата/время начала периода")
    p_usage.set_defaults(func=cmd_usage)

    p_inc = sub.add_parser("incidents", help="список DLP-инцидентов")
    p_inc.add_argument("--since", default=None)
    p_inc.add_argument("--user", default=None)
    p_inc.add_argument("--limit", type=int, default=500)
    p_inc.set_defaults(func=cmd_incidents)

    p_sum = sub.add_parser("summary", help="краткая сводка")
    p_sum.set_defaults(func=cmd_summary)

    p_html = sub.add_parser("html", help="сгенерировать HTML-отчёт")
    p_html.add_argument("--since", default=None)
    p_html.add_argument("--out", default="report_out/report.html")
    p_html.set_defaults(func=cmd_html)

    args = parser.parse_args(argv)

    if not os.path.exists(args.db) and args.db != ":memory:":
        sys.stderr.write(f"[report] БД не найдена: {args.db}. Сначала соберите события через прокси.\n")
        return 1

    with EventStore(args.db) as store:
        return args.func(store, args)


if __name__ == "__main__":
    raise SystemExit(main())
