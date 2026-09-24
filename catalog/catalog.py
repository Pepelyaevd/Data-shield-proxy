"""Каталог провайдеров и классификатор потоков.

Каталог = структурированные данные (домены/суффиксы → провайдер). В MVP держим
их прямо в Python (без внешних зависимостей); формат тривиально переносится в
YAML на следующем шаге. Расширение = добавить запись в PROVIDERS → «подключать
любых агентов» (README).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass(frozen=True)
class Provider:
    id: str  # машинный идентификатор, напр. "anthropic"
    name: str  # человекочитаемое имя
    domains: List[str]  # суффиксы доменов, по которым классифицируем поток
    parser: str = "generic"  # какой парсер контента применять (см. parsers.py)
    known_agents: List[str] = field(default_factory=list)


# Мини-каталог MVP. Стартово — Anthropic (основной кейс), плюс распространённые
# провайдеры для демонстрации расширяемости и классификации.
PROVIDERS: List[Provider] = [
    Provider(
        id="anthropic",
        name="Anthropic",
        domains=["api.anthropic.com", "anthropic.com", "claude.ai"],
        parser="anthropic_messages",
        known_agents=["claude-code", "claude-desktop"],
    ),
    Provider(
        id="openai",
        name="OpenAI",
        domains=["api.openai.com", "openai.com", "chatgpt.com"],
        parser="openai_chat",
        known_agents=["chatgpt-desktop", "openai-cli"],
    ),
    Provider(
        id="google",
        name="Google AI",
        domains=["generativelanguage.googleapis.com", "aiplatform.googleapis.com"],
        parser="generic",
        known_agents=["gemini"],
    ),
    Provider(
        id="cursor",
        name="Cursor",
        domains=["api2.cursor.sh", "cursor.sh", "cursor.com"],
        parser="generic",
        known_agents=["cursor"],
    ),
    Provider(
        id="github_copilot",
        name="GitHub Copilot",
        domains=["copilot-proxy.githubusercontent.com", "api.githubcopilot.com"],
        parser="generic",
        known_agents=["copilot"],
    ),
    Provider(
        id="perplexity",
        name="Perplexity",
        domains=["api.perplexity.ai", "perplexity.ai"],
        parser="generic",
        known_agents=["perplexity"],
    ),
    Provider(
        id="mistral",
        name="Mistral",
        domains=["api.mistral.ai"],
        parser="generic",
        known_agents=["mistral"],
    ),
]

# Индекс «суффикс домена → провайдер» для быстрого сопоставления.
_DOMAIN_INDEX: Dict[str, Provider] = {}
for _p in PROVIDERS:
    for _d in _p.domains:
        _DOMAIN_INDEX[_d.lower()] = _p


# --------------------------------------------------------------------------- #
# «Не-DLP» список: телеметрия / observability / краш-репорты / фичефлаги.
# --------------------------------------------------------------------------- #
# Эти хосты — не каналы утечки промптов, а служебный egress самих агентов
# (Claude Code, IDE, SDK). Инспектировать их DLP-движком бессмысленно: они
# несут хэши, trace-id, base64-пейлоады метрик — доминирующий источник
# false-positive (в первую очередь high_entropy_string). По умолчанию egress
# на них НЕ сканируется (см. ProxyConfig.scan_telemetry / addon).
TELEMETRY_DOMAINS: List[str] = [
    # Observability / APM / логи
    "datadoghq.com", "datadoghq.eu", "ddog-gov.com",
    "sentry.io", "ingest.sentry.io", "ingest.us.sentry.io", "ingest.de.sentry.io",
    "newrelic.com", "nr-data.net",
    "bugsnag.com", "honeycomb.io",
    "elastic-cloud.com",
    # Продуктовая аналитика / метрики
    "segment.io", "segment.com", "amplitude.com", "mixpanel.com",
    "google-analytics.com", "analytics.google.com",
    # Фичефлаги / эксперименты (Claude Code и др.)
    "statsig.com", "featuregates.org", "launchdarkly.com", "events.launchdarkly.com",
    # Инфраструктура доставки телеметрии / краш-репортов
    "crashlytics.com", "app-measurement.com",
]

_TELEMETRY_SET = {d.lower() for d in TELEMETRY_DOMAINS}

# Однозначные бренд-токены телеметрии, которые встречаются в «склеенных» интейк-
# доменах без разделителя-точки (напр. Datadog: browser-intake-datadoghq.com,
# browser-intake-us5-datadoghq.com). Подстрочное совпадение здесь безопасно —
# это фирменные, не переиспользуемые токены.
_TELEMETRY_SUBSTRINGS = ("datadoghq", "ingest.sentry.io", "statsig")


def is_telemetry(host: Optional[str]) -> bool:
    """True, если хост — телеметрия/observability (egress не подлежит DLP-скану).

    Совпадение по суффиксу: 'o123.ingest.sentry.io' попадает под правило так же,
    как точное; плюс подстрочное — для «склеенных» интейк-доменов Datadog
    (browser-intake-*-datadoghq.com).
    """
    if not host:
        return False
    h = host.lower().strip().rstrip(".")
    if ":" in h:  # host:port
        h = h.split(":", 1)[0]
    if h in _TELEMETRY_SET:
        return True
    for domain in _TELEMETRY_SET:
        if h == domain or h.endswith("." + domain):
            return True
    for token in _TELEMETRY_SUBSTRINGS:
        if token in h:
            return True
    return False


def classify(host: Optional[str]) -> Optional[Provider]:
    """Определяет провайдера по хосту назначения (SNI/Host).

    Совпадение по суффиксу: 'api.anthropic.com' → anthropic; поддомены тоже.
    Возвращает None для неизвестных хостов (обрабатываются generic-путём).
    """
    if not host:
        return None
    h = host.lower().strip().rstrip(".")
    if ":" in h:  # host:port
        h = h.split(":", 1)[0]
    # точное совпадение
    if h in _DOMAIN_INDEX:
        return _DOMAIN_INDEX[h]
    # совпадение по суффиксу (поддомены)
    for domain, provider in _DOMAIN_INDEX.items():
        if h == domain or h.endswith("." + domain):
            return provider
    return None
