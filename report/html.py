"""Генерация минимальной read-only HTML-страницы отчёта (без внешних зависимостей)."""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from typing import Optional

from storage import EventStore


def _esc(v) -> str:
    return html.escape("" if v is None else str(v))


def _sig_summary(raw: str) -> str:
    try:
        sigs = json.loads(raw)
    except Exception:
        return _esc(raw)
    chips = []
    for s in sigs:
        sev = s.get("severity", "low")
        det = s.get("detector", "?")
        snip = s.get("snippet", "")
        chips.append(
            f'<span class="chip sev-{_esc(sev)}" title="{_esc(snip)}">{_esc(det)}</span>'
        )
    return " ".join(chips)


def render_html(store: EventStore, since: Optional[str] = None) -> str:
    counts = store.counts()
    users = store.usage_by_user(since=since)
    agents = store.usage_by_agent(since=since)
    incidents = store.incidents(since=since, limit=200)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    user_rows = "".join(
        f"<tr><td>{_esc(r['user'])}</td><td class='num'>{r['requests']}</td>"
        f"<td class='num'>{r['agents']}</td><td class='num'>{r['tokens_in']}</td>"
        f"<td class='num'>{r['tokens_out']}</td>"
        f"<td class='num {'alert' if r['alerts'] else ''}'>{r['alerts']}</td></tr>"
        for r in users
    ) or "<tr><td colspan='6' class='empty'>нет данных</td></tr>"

    agent_rows = "".join(
        f"<tr><td>{_esc(r['agent'])}</td><td>{_esc(r['provider'])}</td>"
        f"<td class='num'>{r['requests']}</td><td class='num'>{r['users']}</td>"
        f"<td class='num {'alert' if r['alerts'] else ''}'>{r['alerts']}</td></tr>"
        for r in agents
    ) or "<tr><td colspan='5' class='empty'>нет данных</td></tr>"

    incident_rows = "".join(
        f"<tr><td class='num'>{r['id']}</td><td>{_esc(r['ts'])}</td>"
        f"<td>{_esc(r['user'])}</td><td>{_esc(r['agent'])}</td>"
        f"<td>{_esc(r['destination'])}</td><td>{_sig_summary(r['matched_signatures'])}</td></tr>"
        for r in incidents
    ) or "<tr><td colspan='6' class='empty'>инцидентов нет</td></tr>"

    return f"""<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Data-Shield-Proxy — отчёт</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 24px;
         background: #f6f7f9; color: #1a1a1a; }}
  @media (prefers-color-scheme: dark) {{ body {{ background:#14161a; color:#e6e6e6; }}
    table {{ background:#1c1f24 !important; }} th {{ background:#252a31 !important; }} }}
  h1 {{ font-size: 20px; margin: 0 0 4px; }}
  .meta {{ color: #888; font-size: 13px; margin-bottom: 20px; }}
  .cards {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 24px; }}
  .card {{ background: #fff; border-radius: 10px; padding: 14px 18px; min-width: 140px;
          box-shadow: 0 1px 3px rgba(0,0,0,.08); }}
  @media (prefers-color-scheme: dark) {{ .card {{ background:#1c1f24; }} }}
  .card .n {{ font-size: 26px; font-weight: 700; }}
  .card .l {{ font-size: 12px; color: #888; text-transform: uppercase; letter-spacing:.04em; }}
  .card.alerts .n {{ color: #d9534f; }}
  h2 {{ font-size: 15px; margin: 24px 0 8px; }}
  table {{ width: 100%; border-collapse: collapse; background:#fff; border-radius: 8px;
          overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.06); font-size: 13px; }}
  th, td {{ text-align: left; padding: 8px 12px; border-bottom: 1px solid rgba(128,128,128,.15); }}
  th {{ background: #eef0f3; font-weight: 600; }}
  td.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
  td.alert {{ color: #d9534f; font-weight: 700; }}
  td.empty {{ text-align:center; color:#999; font-style: italic; }}
  .chip {{ display: inline-block; padding: 1px 7px; border-radius: 10px; font-size: 11px;
          margin: 1px; background:#e3e6ea; }}
  .chip.sev-high, .chip.sev-critical {{ background:#f8d7da; color:#842029; }}
  .chip.sev-medium {{ background:#fff3cd; color:#664d03; }}
  .note {{ margin-top:28px; font-size:12px; color:#999; }}
</style>
</head>
<body>
  <h1>Data-Shield-Proxy — отчёт</h1>
  <div class="meta">Сгенерировано {generated}{(' · период с ' + _esc(since)) if since else ''} · режим alert-only</div>

  <div class="cards">
    <div class="card"><div class="n">{counts['total']}</div><div class="l">событий</div></div>
    <div class="card alerts"><div class="n">{counts['alerts']}</div><div class="l">DLP-алертов</div></div>
    <div class="card"><div class="n">{len(users)}</div><div class="l">пользователей</div></div>
  </div>

  <h2>Частота использования по пользователям</h2>
  <table>
    <thead><tr><th>Пользователь</th><th class="num">Запросы</th><th class="num">Агенты</th>
      <th class="num">Токены in</th><th class="num">Токены out</th><th class="num">Алерты</th></tr></thead>
    <tbody>{user_rows}</tbody>
  </table>

  <h2>По агентам</h2>
  <table>
    <thead><tr><th>Агент</th><th>Провайдер</th><th class="num">Запросы</th>
      <th class="num">Пользователи</th><th class="num">Алерты</th></tr></thead>
    <tbody>{agent_rows}</tbody>
  </table>

  <h2>DLP-инциденты</h2>
  <table>
    <thead><tr><th class="num">#</th><th>Время</th><th>Пользователь</th><th>Агент</th>
      <th>Назначение</th><th>Сигнатуры</th></tr></thead>
    <tbody>{incident_rows}</tbody>
  </table>

  <div class="note">Хранятся метаданные и маскированные сигнатуры — без сырого содержимого промптов
    (минимизация данных). Наведите курсор на сигнатуру, чтобы увидеть маскированный фрагмент.</div>
</body>
</html>"""
