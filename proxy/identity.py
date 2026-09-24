"""Кодирование/декодирование идентичности пользователя через прокси.

Задача (ROADMAP п.6): лаунчер проставляет identity, addon её читает; fallback —
на OS-пользователя / дефолт.

Механизм MVP — стандартный и надёжный: лаунчер задаёт агенту прокси с userinfo
    HTTPS_PROXY=http://<user>:<agent>@proxy-host:port
Клиент передаёт это в заголовке `Proxy-Authorization: Basic base64(user:agent)`
при CONNECT. Пароль здесь несёт не секрет, а имя агента — прокси не аутентифицирует
по нему, только атрибутирует. Это даёт устойчивую привязку к пользователю
(лучше, чем маппинг по IP).

Fallback-порядок в addon: Proxy-Authorization → заголовки X-DSP-* → дефолт.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Optional
from urllib.parse import quote


@dataclass
class Identity:
    user: str = "unknown"
    agent: Optional[str] = None
    device: Optional[str] = None


def encode_proxy_userinfo(user: str, agent: Optional[str] = None) -> str:
    """Возвращает 'user:agent' для вставки в URL прокси (userinfo), URL-безопасно."""
    u = quote(user or "unknown", safe="")
    a = quote(agent or "", safe="")
    return f"{u}:{a}"


def decode_proxy_authorization(header_value: Optional[str]) -> Optional[Identity]:
    """Разбирает 'Basic base64(user:agent)' → Identity. None, если не Basic/битый."""
    if not header_value:
        return None
    parts = header_value.strip().split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "basic":
        return None
    try:
        raw = base64.b64decode(parts[1]).decode("utf-8", "replace")
    except Exception:
        return None
    if ":" in raw:
        user, agent = raw.split(":", 1)
    else:
        user, agent = raw, ""
    from urllib.parse import unquote

    user = unquote(user).strip()
    agent = unquote(agent).strip()
    if not user:
        return None
    return Identity(user=user, agent=agent or None)
