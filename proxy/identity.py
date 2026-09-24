"""Кодирование/декодирование идентичности пользователя через прокси.

Задача (ROADMAP п.6): лаунчер проставляет identity, addon её читает; fallback —
на OS-пользователя / дефолт.

Механизм MVP — стандартный и надёжный: лаунчер задаёт агенту прокси с userinfo
    HTTPS_PROXY=http://<user>:<secret>@proxy-host:port
Клиент передаёт это в заголовке `Proxy-Authorization: Basic base64(user:secret)`
при CONNECT. Здесь:
  - username несёт идентичность пользователя (атрибуция, требование 5);
  - password несёт общий секрет-«ворота» открытого прокси (MVP-защита от абьюза;
    полноценные пользователи/токены/админка — после MVP).

Fallback-порядок в addon: Proxy-Authorization → заголовки X-DSP-* → дефолт.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Optional
from urllib.parse import quote, unquote


@dataclass
class Identity:
    user: str = "unknown"
    secret: Optional[str] = None  # общий секрет-«ворота» (из password userinfo)
    agent: Optional[str] = None   # из заголовка X-DSP-Agent (gateway-режим)
    device: Optional[str] = None


def encode_proxy_userinfo(user: str, secret: Optional[str] = None) -> str:
    """Возвращает 'user:secret' для вставки в URL прокси (userinfo), URL-безопасно."""
    u = quote(user or "unknown", safe="")
    s = quote(secret or "", safe="")
    return f"{u}:{s}"


def decode_proxy_authorization(header_value: Optional[str]) -> Optional[Identity]:
    """Разбирает 'Basic base64(user:secret)' → Identity. None, если не Basic/битый."""
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
        user, secret = raw.split(":", 1)
    else:
        user, secret = raw, ""
    user = unquote(user).strip()
    secret = unquote(secret)
    if not user:
        return None
    return Identity(user=user, secret=secret if secret != "" else None)
