#!/usr/bin/env python3
"""Control Plane — админский Web UI Data-Shield-Proxy (stdlib http.server).

Панель для офицера безопасности вместо CLI-отчётов:
  • Дашборд      — сводка + топ-проблемы за период;
  • Пользователи — частота использования по людям, присвоение уровней риска
                   (yellow / orange / red / black);
  • Клиенты      — использование по агентам/провайдерам;
  • Инциденты    — DLP-алерты с фильтрами по пользователю и периоду.

Аутентификация — по захардкоженным логину/паролю (см. ADMIN_USER / ADMIN_PASSWORD
ниже; переопределяются переменными окружения DSP_ADMIN_USER / DSP_ADMIN_PASSWORD).
Сессия — cookie со случайным токеном (в памяти процесса).

Запуск:  python3 -m controlplane.server        (или: make admin)
         DSP_ADMIN_PORT=9900 python3 -m controlplane.server
Остановка: Ctrl+C.

ВНИМАНИЕ: это MVP-аутентификация «одного администратора». Смените логин/пароль
через переменные окружения. Для продакшена — полноценная авторизация/пользователи.
"""

from __future__ import annotations

import html
import json
import os
import secrets
import sys
import threading
import time
import webbrowser
from datetime import datetime, timedelta, timezone
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from storage import EventStore  # noqa: E402
from storage.db import DEFAULT_DB_PATH, RISK_LEVELS  # noqa: E402

# --------------------------------------------------------------------------- #
# КОНФИГ / АУТЕНТИФИКАЦИЯ  (захардкожено — поменяете позже сами)
# --------------------------------------------------------------------------- #

# Логин/пароль администратора. Значения по умолчанию — заглушка для MVP.
# Переопределяются переменными окружения без правки кода.
ADMIN_USER = os.environ.get("DSP_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("DSP_ADMIN_PASSWORD", "ChangeMe!DSP-2026")

SESSION_COOKIE = "dsp_admin_session"
SESSION_TTL = 8 * 3600  # 8 часов

BIND_HOST = os.environ.get("DSP_ADMIN_HOST", "127.0.0.1")
BIND_PORT = int(os.environ.get("DSP_ADMIN_PORT", "9900"))
DB_PATH = os.environ.get("DSP_DB_PATH", DEFAULT_DB_PATH)

# token -> expires_at (epoch). Живёт в памяти процесса; рестарт = разлогин.
_SESSIONS: Dict[str, float] = {}
_SESSIONS_LOCK = threading.Lock()


def _new_session() -> str:
    token = secrets.token_urlsafe(32)
    with _SESSIONS_LOCK:
        _SESSIONS[token] = time.time() + SESSION_TTL
    return token


def _session_valid(token: Optional[str]) -> bool:
    if not token:
        return False
    with _SESSIONS_LOCK:
        exp = _SESSIONS.get(token)
        if exp is None:
            return False
        if exp < time.time():
            _SESSIONS.pop(token, None)
            return False
        return True


def _drop_session(token: Optional[str]) -> None:
    if token:
        with _SESSIONS_LOCK:
            _SESSIONS.pop(token, None)


def _check_credentials(user: str, password: str) -> bool:
    # secrets.compare_digest — сравнение постоянного времени (защита от тайминга).
    return (
        secrets.compare_digest(user or "", ADMIN_USER)
        and secrets.compare_digest(password or "", ADMIN_PASSWORD)
    )


# --------------------------------------------------------------------------- #
# ПЕРИОДЫ
# --------------------------------------------------------------------------- #

# Пресеты периода: ключ → (человекочитаемое имя, timedelta | None).
PERIODS: Dict[str, Tuple[str, Optional[timedelta]]] = {
    "24h": ("24 часа", timedelta(hours=24)),
    "7d": ("7 дней", timedelta(days=7)),
    "30d": ("30 дней", timedelta(days=30)),
    "90d": ("90 дней", timedelta(days=90)),
    "all": ("всё время", None),
}
DEFAULT_PERIOD = "7d"


def _resolve_period(params: Dict[str, List[str]]) -> Dict[str, Any]:
    """Возвращает {since, until, key, label, custom} из query-параметров.

    Приоритет у явных since/until (даты YYYY-MM-DD); иначе пресет period.
    """
    since_raw = (params.get("since", [""])[0] or "").strip()
    until_raw = (params.get("until", [""])[0] or "").strip()
    period = (params.get("period", [""])[0] or "").strip()

    if since_raw or until_raw:
        since_iso = _day_start(since_raw) if since_raw else None
        until_iso = _day_end(until_raw) if until_raw else None
        label = "период: " + (since_raw or "…") + " — " + (until_raw or "…")
        return {
            "since": since_iso,
            "until": until_iso,
            "key": "custom",
            "label": label,
            "since_raw": since_raw,
            "until_raw": until_raw,
            "custom": True,
        }

    if period not in PERIODS:
        period = DEFAULT_PERIOD
    name, delta = PERIODS[period]
    since_iso = None
    if delta is not None:
        since_iso = (datetime.now(timezone.utc) - delta).isoformat()
    return {
        "since": since_iso,
        "until": None,
        "key": period,
        "label": name,
        "since_raw": "",
        "until_raw": "",
        "custom": False,
    }


def _day_start(d: str) -> Optional[str]:
    try:
        dt = datetime.strptime(d, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except ValueError:
        return None


def _day_end(d: str) -> Optional[str]:
    try:
        dt = datetime.strptime(d, "%Y-%m-%d").replace(
            hour=23, minute=59, second=59, tzinfo=timezone.utc
        )
        return dt.isoformat()
    except ValueError:
        return None


def _period_query(pr: Dict[str, Any]) -> str:
    """Сериализует текущий период в query-строку для переносимых ссылок."""
    if pr["custom"]:
        parts = []
        if pr["since_raw"]:
            parts.append("since=" + pr["since_raw"])
        if pr["until_raw"]:
            parts.append("until=" + pr["until_raw"])
        return "&".join(parts)
    return "period=" + pr["key"]


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #

def _esc(v: Any) -> str:
    return html.escape("" if v is None else str(v))


LEVEL_META = {
    "yellow": ("🟡", "Жёлтый", "Наблюдение"),
    "orange": ("🟠", "Оранжевый", "Повышенное внимание"),
    "red": ("🔴", "Красный", "Высокий риск"),
    "black": ("⚫", "Чёрный", "Критично / блок"),
}

STYLE = """
:root{color-scheme:light dark;
 --bg:#f6f7f9;--fg:#1a1a1a;--card:#fff;--muted:#8a8f98;--line:rgba(128,128,128,.18);
 --th:#eef0f3;--accent:#2563eb;--alert:#d9534f;}
@media(prefers-color-scheme:dark){:root{
 --bg:#14161a;--fg:#e6e6e6;--card:#1c1f24;--muted:#8a8f98;--line:rgba(128,128,128,.22);
 --th:#252a31;}}
*{box-sizing:border-box}
body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:var(--bg);color:var(--fg)}
header.top{background:var(--card);border-bottom:1px solid var(--line);padding:0 20px;
 display:flex;align-items:center;gap:22px;position:sticky;top:0;z-index:10}
header.top .brand{font-weight:700;font-size:15px;padding:14px 0}
header.top .brand .shield{color:#0b8a4b}
nav.tabs{display:flex;gap:2px;flex:1}
nav.tabs a{padding:16px 14px;font-size:14px;color:var(--muted);text-decoration:none;
 border-bottom:2px solid transparent}
nav.tabs a.active{color:var(--fg);border-bottom-color:var(--accent);font-weight:600}
nav.tabs a:hover{color:var(--fg)}
header.top .who{font-size:12px;color:var(--muted)}
header.top .who a{color:var(--accent);text-decoration:none;margin-left:10px}
main{max-width:1080px;margin:0 auto;padding:22px 20px 60px}
h1{font-size:19px;margin:0 0 2px}
.sub{color:var(--muted);font-size:13px;margin-bottom:18px}
.periodbar{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin:0 0 20px;
 background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 12px}
.periodbar .lbl{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.periodbar a.chip{font-size:13px;text-decoration:none;color:var(--fg);padding:5px 11px;
 border-radius:16px;background:var(--th)}
.periodbar a.chip.on{background:var(--accent);color:#fff;font-weight:600}
.periodbar form{display:flex;align-items:center;gap:6px;margin-left:auto}
.periodbar input[type=date]{padding:5px 8px;border:1px solid var(--line);border-radius:7px;
 background:var(--bg);color:var(--fg);font-size:13px}
.periodbar button{padding:6px 12px;border:0;border-radius:7px;background:var(--accent);
 color:#fff;font-size:13px;cursor:pointer}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 18px;min-width:150px}
.card .n{font-size:26px;font-weight:700}
.card .l{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.card.alerts .n{color:var(--alert)}
h2{font-size:15px;margin:26px 0 8px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);
 border-radius:8px;overflow:hidden;font-size:13px}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:middle}
th{background:var(--th);font-weight:600}
tr:last-child td{border-bottom:0}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
td.alert{color:var(--alert);font-weight:700}
td.empty{text-align:center;color:var(--muted);font-style:italic;padding:22px}
.badge{display:inline-block;padding:2px 9px;border-radius:12px;font-size:12px;font-weight:600}
.badge.yellow{background:#fff3cd;color:#664d03}
.badge.orange{background:#ffe1c2;color:#8a4b00}
.badge.red{background:#f8d7da;color:#842029}
.badge.black{background:#2b2b2b;color:#fff}
.badge.none{background:var(--th);color:var(--muted);font-weight:400}
.chip{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;margin:1px;background:var(--th)}
.chip.sev-high,.chip.sev-critical{background:#f8d7da;color:#842029}
.chip.sev-medium{background:#fff3cd;color:#664d03}
.sev-dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px;vertical-align:middle}
.sev-dot.low{background:#8a8f98}.sev-dot.medium{background:#e0a800}
.sev-dot.high{background:#e8590c}.sev-dot.critical{background:#d9534f}
.note{margin-top:30px;font-size:12px;color:var(--muted)}
.bar{height:8px;border-radius:4px;background:var(--accent);min-width:2px;display:inline-block;vertical-align:middle}
.barwrap{display:inline-block;width:120px;background:var(--th);border-radius:4px;overflow:hidden;vertical-align:middle;margin-right:8px}
.barwrap .bar{display:block}
"""

LOGIN_PAGE = """<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Control Plane — вход</title><style>%s
.login{max-width:340px;margin:9vh auto;background:var(--card);border:1px solid var(--line);
 border-radius:14px;padding:26px}
.login h1{text-align:center;font-size:17px;margin:0 0 4px}
.login .sub{text-align:center}
.login label{display:block;font-size:12px;color:var(--muted);margin:12px 0 4px}
.login input{width:100%%;padding:9px 11px;border:1px solid var(--line);border-radius:8px;
 background:var(--bg);color:var(--fg);font-size:14px}
.login button{width:100%%;margin-top:18px;padding:11px;border:0;border-radius:8px;
 background:var(--accent);color:#fff;font-size:14px;font-weight:600;cursor:pointer}
.err{background:#f8d7da;color:#842029;padding:9px 12px;border-radius:8px;font-size:13px;margin-top:14px}
</style></head><body>
<div class="login">
 <h1>🛡 Data-Shield-Proxy</h1>
 <div class="sub">Control Plane · вход для офицера безопасности</div>
 %s
 <form method="post" action="/login">
  <label>Логин</label><input name="user" autofocus autocomplete="username">
  <label>Пароль</label><input name="password" type="password" autocomplete="current-password">
  <button type="submit">Войти</button>
 </form>
</div></body></html>"""


def _login_html(error: Optional[str] = None) -> str:
    err = f'<div class="err">{_esc(error)}</div>' if error else ""
    return LOGIN_PAGE % (STYLE, err)


def _layout(active: str, pr: Dict[str, Any], title: str, body: str,
            show_period: bool = True) -> str:
    tabs = [
        ("/", "Дашборд", "dashboard"),
        ("/users", "Пользователи", "users"),
        ("/clients", "Клиенты", "clients"),
        ("/incidents", "Инциденты", "incidents"),
    ]
    q = _period_query(pr)
    nav = "".join(
        f'<a class="{"active" if key == active else ""}" '
        f'href="{href}{("?" + q) if q and href != "#" else ""}">{_esc(label)}</a>'
        for href, label, key in tabs
    )
    period_bar = _period_bar(active, pr) if show_period else ""
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(title)} — Control Plane</title><style>{STYLE}</style></head><body>
<header class="top">
 <div class="brand"><span class="shield">🛡</span> Data-Shield-Proxy</div>
 <nav class="tabs">{nav}</nav>
 <div class="who">{_esc(ADMIN_USER)}<a href="/logout">выйти</a></div>
</header>
<main>
 <h1>{_esc(title)}</h1>
 <div class="sub">период: {_esc(pr['label'])}</div>
 {period_bar}
 {body}
</main></body></html>"""


def _period_bar(active: str, pr: Dict[str, Any]) -> str:
    base = {"dashboard": "/", "users": "/users",
            "clients": "/clients", "incidents": "/incidents"}[active]
    chips = []
    for key, (name, _delta) in PERIODS.items():
        on = "on" if (not pr["custom"] and pr["key"] == key) else ""
        chips.append(f'<a class="chip {on}" href="{base}?period={key}">{_esc(name)}</a>')
    chips_html = "".join(chips)
    return f"""<div class="periodbar">
 <span class="lbl">Период</span>
 {chips_html}
 <form method="get" action="{base}">
   <input type="date" name="since" value="{_esc(pr['since_raw'])}">
   <input type="date" name="until" value="{_esc(pr['until_raw'])}">
   <button type="submit">Применить</button>
 </form>
</div>"""


def _sig_chips(raw: str) -> str:
    try:
        sigs = json.loads(raw)
    except Exception:
        return _esc(raw)
    chips = []
    for s in sigs:
        sev = s.get("severity", "low")
        det = s.get("detector", "?")
        snip = s.get("snippet", "")
        cnt = s.get("count", 1)
        label = _esc(det) + (f" ×{cnt}" if cnt and cnt > 1 else "")
        chips.append(f'<span class="chip sev-{_esc(sev)}" title="{_esc(snip)}">{label}</span>')
    return " ".join(chips) or "—"


def _level_badge(level: Optional[str]) -> str:
    if not level or level not in LEVEL_META:
        return '<span class="badge none">не задан</span>'
    icon, name, _desc = LEVEL_META[level]
    return f'<span class="badge {level}">{icon} {_esc(name)}</span>'


# ---- страницы -------------------------------------------------------------- #

def page_dashboard(store: EventStore, pr: Dict[str, Any]) -> str:
    c = store.counts(since=pr["since"], until=pr["until"])
    problems = store.top_problems(since=pr["since"], until=pr["until"], limit=12)
    users = store.usage_by_user(since=pr["since"], until=pr["until"])
    risk = store.user_risk(since=pr["since"], until=pr["until"])

    cards = f"""<div class="cards">
     <div class="card"><div class="n">{c['total']}</div><div class="l">событий</div></div>
     <div class="card alerts"><div class="n">{c['alerts']}</div><div class="l">DLP-алертов</div></div>
     <div class="card"><div class="n">{c['users']}</div><div class="l">пользователей</div></div>
     <div class="card"><div class="n">{len(problems)}</div><div class="l">типов проблем</div></div>
    </div>"""

    max_hits = max((p["hits"] for p in problems), default=1) or 1
    prob_rows = ""
    for p in problems:
        width = int(100 * p["hits"] / max_hits)
        prob_rows += (
            f"<tr><td><span class='sev-dot {_esc(p['severity'])}'></span>"
            f"{_esc(p['detector'])}</td>"
            f"<td>{_esc(p['category'])}</td>"
            f"<td><span class='chip sev-{_esc(p['severity'])}'>{_esc(p['severity'])}</span></td>"
            f"<td class='num'>{p['events']}</td>"
            f"<td class='num'>{p['users']}</td>"
            f"<td class='num'><span class='barwrap'><span class='bar' style='width:{width}%'></span></span>{p['hits']}</td></tr>"
        )
    prob_rows = prob_rows or "<tr><td colspan='6' class='empty'>проблем за период не зафиксировано</td></tr>"

    # Топ пользователей по алертам за период.
    top_users = sorted(users, key=lambda r: (r["alerts"] or 0), reverse=True)[:8]
    tu_rows = ""
    for r in top_users:
        lvl = risk.get(r["user"], {}).get("level")
        tu_rows += (
            f"<tr><td>{_esc(r['user'])}</td><td>{_level_badge(lvl)}</td>"
            f"<td class='num'>{r['requests']}</td>"
            f"<td class='num {'alert' if r['alerts'] else ''}'>{r['alerts']}</td></tr>"
        )
    tu_rows = tu_rows or "<tr><td colspan='4' class='empty'>нет данных</td></tr>"

    body = cards + f"""
    <h2>Топ проблем за период</h2>
    <table>
     <thead><tr><th>Детектор</th><th>Категория</th><th>Серьёзность</th>
       <th class="num">Событий</th><th class="num">Пользователей</th><th class="num">Срабатываний</th></tr></thead>
     <tbody>{prob_rows}</tbody>
    </table>

    <h2>Пользователи с наибольшим числом алертов</h2>
    <table>
     <thead><tr><th>Пользователь</th><th>Уровень</th>
       <th class="num">Запросы</th><th class="num">Алерты</th></tr></thead>
     <tbody>{tu_rows}</tbody>
    </table>
    """
    return _layout("dashboard", pr, "Дашборд", body)


def page_users(store: EventStore, pr: Dict[str, Any]) -> str:
    users = store.usage_by_user(since=pr["since"], until=pr["until"])
    risk = store.user_risk(since=pr["since"], until=pr["until"])

    # Сортировка: сначала пользователи с наивысшим уровнем риска.
    def _rank(r):
        info = risk.get(r["user"] or "", {})
        return (RISK_LEVELS.index(info["level"]) + 1) if info.get("level") else 0
    users = sorted(users, key=lambda r: (_rank(r), r["alerts"] or 0), reverse=True)

    rows = ""
    for r in users:
        user = r["user"] or ""
        info = risk.get(user, {})
        cur = info.get("level")
        reason = info.get("reason", "")
        reason_html = (f"<span class='sub' style='font-size:11px'>{_esc(reason)}</span>"
                       if cur else "<span class='sub' style='font-size:11px'>—</span>")
        rows += (
            f"<tr><td><b>{_esc(user)}</b></td>"
            f"<td>{_level_badge(cur)}</td>"
            f"<td>{reason_html}</td>"
            f"<td class='num'>{r['requests']}</td>"
            f"<td class='num'>{r['agents']}</td>"
            f"<td class='num'>{r['tokens_in']}</td>"
            f"<td class='num {'alert' if r['alerts'] else ''}'>{r['alerts']}</td></tr>"
        )
    rows = rows or "<tr><td colspan='7' class='empty'>нет данных за период</td></tr>"

    legend = " · ".join(
        f"{LEVEL_META[lv][0]} {LEVEL_META[lv][1]} — {LEVEL_META[lv][2]}"
        for lv in RISK_LEVELS
    )

    body = f"""
    <table>
     <thead><tr><th>Пользователь</th><th>Уровень риска</th><th>Основание</th>
       <th class="num">Запросы</th><th class="num">Агенты</th>
       <th class="num">Токены in</th><th class="num">Алерты</th></tr></thead>
     <tbody>{rows}</tbody>
    </table>
    <div class="note"><b>Уровень присваивается системой автоматически</b> по истории
     DLP-срабатываний за выбранный период (не вручную). Шкала: {_esc(legend)}.<br>
     Правило: ⚫ чёрный — ≥2 критических находок · 🔴 красный — ≥1 критическая или ≥3 high ·
     🟠 оранжевый — ≥1 high или ≥2 medium · 🟡 жёлтый — есть medium/low.
     Пользователи без срабатываний за период уровня не получают.</div>
    """
    return _layout("users", pr, "Пользователи", body)


def page_clients(store: EventStore, pr: Dict[str, Any]) -> str:
    agents = store.usage_by_agent(since=pr["since"], until=pr["until"])
    rows = ""
    for r in agents:
        rows += (
            f"<tr><td>{_esc(r['agent'])}</td><td>{_esc(r['provider'])}</td>"
            f"<td class='num'>{r['requests']}</td>"
            f"<td class='num'>{r['users']}</td>"
            f"<td class='num {'alert' if r['alerts'] else ''}'>{r['alerts']}</td></tr>"
        )
    rows = rows or "<tr><td colspan='5' class='empty'>нет данных за период</td></tr>"
    body = f"""
    <table>
     <thead><tr><th>Клиент (агент)</th><th>Провайдер</th>
       <th class="num">Запросы</th><th class="num">Пользователи</th><th class="num">Алерты</th></tr></thead>
     <tbody>{rows}</tbody>
    </table>
    <div class="note">«Клиент» — машинное имя агента (claude-code, …), через который шёл трафик.</div>
    """
    return _layout("clients", pr, "Клиенты", body)


def page_incidents(store: EventStore, pr: Dict[str, Any],
                   user_filter: Optional[str]) -> str:
    incidents = store.incidents(
        since=pr["since"], until=pr["until"], user=user_filter or None, limit=500
    )
    risk = store.user_risk(since=pr["since"], until=pr["until"])
    all_users = store.distinct_users()
    q = _period_query(pr)

    # выпадающий фильтр по пользователю
    opts = '<option value="">— все пользователи —</option>'
    for u in all_users:
        sel = " selected" if u == user_filter else ""
        opts += f'<option value="{_esc(u)}"{sel}>{_esc(u)}</option>'
    filt = (
        f'<form method="get" action="/incidents" style="margin-bottom:16px">'
        + (f'<input type="hidden" name="period" value="{_esc(pr["key"])}">'
           if not pr["custom"] else
           f'<input type="hidden" name="since" value="{_esc(pr["since_raw"])}">'
           f'<input type="hidden" name="until" value="{_esc(pr["until_raw"])}">')
        + f'<select name="user" onchange="this.form.submit()" '
          f'style="padding:6px 9px;border:1px solid var(--line);border-radius:7px;'
          f'background:var(--bg);color:var(--fg)">{opts}</select></form>'
    )

    rows = ""
    for r in incidents:
        lvl = risk.get(r["user"], {}).get("level")
        rows += (
            f"<tr><td class='num'>{r['id']}</td>"
            f"<td>{_esc(r['ts'][:19].replace('T',' '))}</td>"
            f"<td>{_esc(r['user'])} {_level_badge(lvl)}</td>"
            f"<td>{_esc(r['agent'])}</td>"
            f"<td>{_esc(r['destination'])}</td>"
            f"<td>{_sig_chips(r['matched_signatures'])}</td></tr>"
        )
    rows = rows or "<tr><td colspan='6' class='empty'>инцидентов за период не найдено</td></tr>"

    body = filt + f"""
    <table>
     <thead><tr><th class="num">#</th><th>Время (UTC)</th><th>Пользователь</th>
       <th>Клиент</th><th>Назначение</th><th>Сигнатуры</th></tr></thead>
     <tbody>{rows}</tbody>
    </table>
    <div class="note">Показаны alert-события (до 500). Наведите курсор на сигнатуру —
     увидите маскированный фрагмент. Сырое содержимое промптов не хранится.</div>
    """
    return _layout("incidents", pr, "Инциденты", body)


# --------------------------------------------------------------------------- #
# HTTP-обработчик
# --------------------------------------------------------------------------- #

class Handler(BaseHTTPRequestHandler):
    server_version = "DSP-ControlPlane"

    def log_message(self, *a):  # тихо
        pass

    # ---- утилиты ответа --------------------------------------------------- #

    def _send(self, code: int, body: str, ctype="text/html; charset=utf-8",
              extra_headers: Optional[List[Tuple[str, str]]] = None):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra_headers or []):
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _redirect(self, location: str,
                  extra_headers: Optional[List[Tuple[str, str]]] = None):
        self.send_response(303)
        self.send_header("Location", location)
        for k, v in (extra_headers or []):
            self.send_header(k, v)
        self.end_headers()

    def _cookie_token(self) -> Optional[str]:
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        try:
            c = cookies.SimpleCookie(raw)
        except Exception:
            return None
        m = c.get(SESSION_COOKIE)
        return m.value if m else None

    def _authed(self) -> bool:
        return _session_valid(self._cookie_token())

    def _read_form(self) -> Dict[str, str]:
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        parsed = parse_qs(raw, keep_blank_values=True)
        return {k: v[0] for k, v in parsed.items()}

    @property
    def _store(self) -> EventStore:
        # По соединению новый EventStore не нужен — используем общий на процесс.
        return self.server.store  # type: ignore[attr-defined]

    # ---- маршрутизация ---------------------------------------------------- #

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query, keep_blank_values=True)

        if path == "/login":
            if self._authed():
                self._redirect("/")
            else:
                self._send(200, _login_html())
            return
        if path == "/logout":
            _drop_session(self._cookie_token())
            expire = f"{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"
            self._redirect("/login", [("Set-Cookie", expire)])
            return

        if not self._authed():
            self._redirect("/login")
            return

        pr = _resolve_period(params)
        try:
            if path == "/" or path == "/index.html":
                self._send(200, page_dashboard(self._store, pr))
            elif path == "/users":
                self._send(200, page_users(self._store, pr))
            elif path == "/clients":
                self._send(200, page_clients(self._store, pr))
            elif path == "/incidents":
                user_filter = (params.get("user", [""])[0] or "").strip()
                self._send(200, page_incidents(self._store, pr, user_filter))
            else:
                self._send(404, _layout("dashboard", pr, "404",
                                        "<div class='note'>Страница не найдена.</div>"))
        except Exception as e:  # не роняем сервер на кривом запросе
            self._send(500, _layout("dashboard", pr, "Ошибка",
                                    f"<div class='note'>Внутренняя ошибка: {_esc(e)}</div>"))

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/login":
            form = self._read_form()
            if _check_credentials(form.get("user", ""), form.get("password", "")):
                token = _new_session()
                cookie = (f"{SESSION_COOKIE}={token}; Path=/; Max-Age={SESSION_TTL}; "
                          f"HttpOnly; SameSite=Lax")
                self._redirect("/", [("Set-Cookie", cookie)])
            else:
                self._send(401, _login_html("Неверный логин или пароль."))
            return

        if not self._authed():
            self._redirect("/login")
            return

        # Уровни риска присваиваются системой автоматически — ручных POST-действий
        # по их изменению нет.
        self._send(404, "not found", "text/plain")


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

def main() -> int:
    if not os.path.exists(DB_PATH) and DB_PATH != ":memory:":
        sys.stderr.write(
            f"[control-plane] БД не найдена: {DB_PATH}. "
            f"Сначала соберите события через прокси (или запустите make demo).\n"
        )
        # Всё равно поднимаем UI — EventStore создаст пустую БД.

    store = EventStore(DB_PATH)
    httpd = ThreadingHTTPServer((BIND_HOST, BIND_PORT), Handler)
    httpd.store = store  # type: ignore[attr-defined]
    url = f"http://{BIND_HOST}:{BIND_PORT}/"
    print("Data-Shield-Proxy · Control Plane (админский Web UI)")
    print(f"  URL:   {url}")
    print(f"  Логин: {ADMIN_USER}   (пароль — см. DSP_ADMIN_PASSWORD / код)")
    print("  Ctrl+C для остановки.")
    if os.environ.get("DSP_ADMIN_NO_BROWSER") != "1":
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nОстановлено.")
    finally:
        httpd.shutdown()
        store.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
