#!/usr/bin/env python3
"""Managed Launcher — управляемый запуск агентов с параметрами прокси и identity.

Перехватывается только трафик запущенного агента (адресный прокси): лаунчер
проставляет env/флаги прокси + доверие к корпоративному CA + идентичность
пользователя, затем передаёт управление агенту.

Примеры:
    # CLI-агент (Claude Code), пользователь alice:
    python3 launcher/launch.py --profile cli --user alice --agent claude-code -- claude

    # любой CLI, проверка через curl:
    python3 launcher/launch.py --profile cli --user bob -- curl https://api.anthropic.com/

    # desktop-агент:
    python3 launcher/launch.py --profile desktop --user carol --agent chatgpt-desktop -- \
        /Applications/ChatGPT.app/Contents/MacOS/ChatGPT

Подключить нового агента: добавить профиль в launcher/profiles.json (какие env/
флаги проставить) и запись провайдера в catalog/catalog.py (домены → парсер).
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import socket
import sys
from typing import Dict
from urllib.parse import urlsplit, urlunsplit

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from proxy.identity import encode_proxy_userinfo  # noqa: E402

PROFILES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "profiles.json")
DEFAULT_PROXY = os.environ.get("DSP_PROXY", "http://127.0.0.1:8080")
DEFAULT_CA = os.environ.get(
    "DSP_CA", os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")
)
DEFAULT_NO_PROXY = os.environ.get("DSP_NO_PROXY", "localhost,127.0.0.1,::1")
DEFAULT_SECRET = os.environ.get("DSP_PROXY_SECRET", "123456")


def load_profiles() -> Dict:
    with open(PROFILES_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _proxy_with_identity(proxy_url: str, user: str, secret: str) -> str:
    """Встраивает userinfo (user:secret) в URL прокси: user — атрибуция, secret — ворота."""
    parts = urlsplit(proxy_url)
    host = parts.hostname or "127.0.0.1"
    netloc = host if parts.port is None else f"{host}:{parts.port}"
    userinfo = encode_proxy_userinfo(user, secret)
    return urlunsplit((parts.scheme or "http", f"{userinfo}@{netloc}", "", "", ""))


def _hostport(proxy_url: str) -> str:
    parts = urlsplit(proxy_url)
    host = parts.hostname or "127.0.0.1"
    port = parts.port or 8080
    return f"{host}:{port}"


def build_environment(profile: Dict, subs: Dict[str, str]) -> Dict[str, str]:
    env = dict(os.environ)
    for key, template in profile.get("env", {}).items():
        env[key] = template.format(**subs)
    # для gateway-режима также прокидываем identity в заголовки (если агент это умеет)
    env.setdefault("DSP_USER", subs["user"])
    env.setdefault("DSP_AGENT", subs["agent"])
    return env


def build_command(profile: Dict, cmd: list, subs: Dict[str, str]) -> list:
    flags = [f.format(**subs) for f in profile.get("flags", [])]
    if not flags:
        return cmd
    # флаги вставляем после исполняемого файла: <exe> <flags...> <args...>
    return [cmd[0]] + flags + cmd[1:]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Managed Launcher: запуск агента через корпоративный прокси.",
        epilog="Команду агента указывайте после '--'.",
    )
    parser.add_argument("--profile", default="cli", help="имя профиля из profiles.json (cli|desktop|...)")
    parser.add_argument("--user", default=None, help="идентичность пользователя (по умолчанию — OS-логин)")
    parser.add_argument("--agent", default="generic", help="машинное имя агента (claude-code, chatgpt-desktop, ...)")
    parser.add_argument("--proxy", default=DEFAULT_PROXY, help=f"URL прокси (по умолчанию {DEFAULT_PROXY})")
    parser.add_argument("--secret", default=DEFAULT_SECRET, help="секрет-ворота прокси (по умолчанию из DSP_PROXY_SECRET)")
    parser.add_argument("--ca", default=DEFAULT_CA, help="путь к корпоративному CA-сертификату (PEM)")
    parser.add_argument("--no-proxy", default=DEFAULT_NO_PROXY, help="список исключений NO_PROXY")
    parser.add_argument("--dry-run", action="store_true", help="показать, что будет запущено, и выйти")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="-- <команда агента> [аргументы]")
    args = parser.parse_args(argv)

    cmd = args.command
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        parser.error("не указана команда агента (после '--')")

    profiles = load_profiles()
    if args.profile not in profiles or args.profile.startswith("_"):
        parser.error(
            f"неизвестный профиль '{args.profile}'. Доступны: "
            + ", ".join(k for k in profiles if not k.startswith("_"))
        )
    profile = profiles[args.profile]

    user = args.user or getpass.getuser()
    if not os.path.exists(args.ca):
        sys.stderr.write(
            f"[dsp-launch] ВНИМАНИЕ: CA не найден по пути {args.ca}. "
            "TLS-инспекция не будет доверенной, пока CA не установлен "
            "(см. deploy/install-ca.sh).\n"
        )

    subs = {
        "proxy_url": _proxy_with_identity(args.proxy, user, args.secret),
        "proxy_hostport": _hostport(args.proxy),
        "ca_path": args.ca,
        "no_proxy": args.no_proxy,
        "user": user,
        "agent": args.agent,
        "device": socket.gethostname(),
    }

    env = build_environment(profile, subs)
    run_cmd = build_command(profile, cmd, subs)

    if args.dry_run:
        print(f"# profile : {args.profile} ({profile.get('description','')})")
        print(f"# user    : {user}")
        print(f"# agent   : {args.agent}")
        print(f"# proxy   : {args.proxy}")
        print(f"# secret  : {'(задан)' if args.secret else '(нет)'}")
        print(f"# ca      : {args.ca}")
        print("# env overrides:")
        for k in profile.get("env", {}):
            # прячем креды прокси в выводе
            shown = env[k]
            if "@" in shown and "://" in shown:
                scheme, rest = shown.split("://", 1)
                shown = scheme + "://***@" + rest.split("@", 1)[1]
            print(f"#   {k}={shown}")
        print("# exec   :", " ".join(run_cmd))
        return 0

    try:
        os.execvpe(run_cmd[0], run_cmd, env)
    except FileNotFoundError:
        sys.stderr.write(f"[dsp-launch] не найден исполняемый файл: {run_cmd[0]}\n")
        return 127
    return 0  # недостижимо при успешном execvpe


if __name__ == "__main__":
    raise SystemExit(main())
