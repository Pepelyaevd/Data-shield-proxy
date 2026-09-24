"""Конфигурация прокси-addon (через переменные окружения).

Все параметры имеют разумные значения по умолчанию, чтобы addon запускался
«из коробки» в alert-only режиме.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


def _env_bool(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


@dataclass
class ProxyConfig:
    db_path: str = os.environ.get("DSP_DB_PATH", "data/events.db")
    default_user: str = os.environ.get("DSP_DEFAULT_USER", "unknown")
    scan_responses: bool = _env_bool("DSP_SCAN_RESPONSES", True)
    max_body_bytes: int = _env_int("DSP_MAX_BODY", 2_000_000)
    enforce: bool = _env_bool("DSP_ENFORCE", False)  # False = alert-only (MVP)

    # Простейшая защита открытого прокси (MVP): общий секрет-«ворота».
    # Клиент подключается как http://<user>:<secret>@proxy:8080 — пароль (secret)
    # проверяется как ворота, username идёт в атрибуцию. Полноценные пользователи/
    # админка — после MVP. Пустой secret отключает проверку.
    proxy_secret: str = os.environ.get("DSP_PROXY_SECRET", "123456")
    # Если задан — username тоже должен точно совпасть (жёсткая связка login/secret).
    proxy_user: str = os.environ.get("DSP_PROXY_USER", "")

    @property
    def auth_required(self) -> bool:
        return bool(self.proxy_secret)

    @classmethod
    def from_env(cls) -> "ProxyConfig":
        return cls()
