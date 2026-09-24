"""Парсеры тела запросов/ответов по провайдерам.

Задача — извлечь из тела человекочитаемый текст (промпт/ответ) для DLP, а также
метаданные (model, tokens). У каждого API своя схема; для неизвестных агентов —
generic JSON/текстовый fallback (README → «Парсеры контента по провайдерам»).

Парсеры устойчивы к мусору: любая ошибка → максимально общий fallback, не падаем.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, List, Optional


MAX_TEXT = 200_000  # предохранитель против гигантских тел


@dataclass
class ParsedContent:
    text: str = ""  # извлечённый текст для сканирования DLP
    model: Optional[str] = None
    tokens_in: Optional[int] = None
    tokens_out: Optional[int] = None
    parser: str = "generic"
    extra: dict = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Утилиты
# --------------------------------------------------------------------------- #

def _to_text(body: Any) -> str:
    if body is None:
        return ""
    if isinstance(body, bytes):
        return body.decode("utf-8", "replace")
    return str(body)


def _json_or_none(body: Any) -> Optional[Any]:
    try:
        return json.loads(_to_text(body))
    except Exception:
        return None


def _extract_content_text(content: Any, acc: List[str]) -> None:
    """Достаёт текст из поля content, которое бывает строкой или списком блоков.

    Поддерживает блоки Anthropic/OpenAI: text, tool_use(input), tool_result,
    вложенный content. Изображения/бинарь пропускаются.
    """
    if content is None:
        return
    if isinstance(content, str):
        acc.append(content)
        return
    if isinstance(content, list):
        for block in content:
            if isinstance(block, str):
                acc.append(block)
            elif isinstance(block, dict):
                btype = block.get("type")
                if "text" in block and isinstance(block["text"], str):
                    acc.append(block["text"])
                elif btype == "tool_use" and "input" in block:
                    acc.append(json.dumps(block["input"], ensure_ascii=False))
                elif btype == "tool_result":
                    _extract_content_text(block.get("content"), acc)
                elif btype == "input_text" and isinstance(block.get("text"), str):
                    acc.append(block["text"])
        return
    if isinstance(content, dict):
        _extract_content_text(content.get("content"), acc)


def _walk_strings(obj: Any, acc: List[str], depth: int = 0) -> None:
    """Рекурсивно собирает все строковые значения из JSON (generic-fallback)."""
    if depth > 30:
        return
    if isinstance(obj, str):
        acc.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _walk_strings(v, acc, depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            _walk_strings(v, acc, depth + 1)


def _clip(text: str) -> str:
    return text[:MAX_TEXT]


def _as_int(v: Any) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------- #
# SSE (streaming) — best-effort агрегация текстовых дельт
# --------------------------------------------------------------------------- #

def _parse_sse_text(body: Any) -> List[str]:
    parts: List[str] = []
    for line in _to_text(body).splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        payload = line[len("data:"):].strip()
        if not payload or payload == "[DONE]":
            continue
        obj = _json_or_none(payload)
        if obj is None:
            continue
        # Anthropic: content_block_delta → delta.text
        delta = obj.get("delta") if isinstance(obj, dict) else None
        if isinstance(delta, dict):
            if isinstance(delta.get("text"), str):
                parts.append(delta["text"])
            # OpenAI streaming: choices[].delta.content
        if isinstance(obj, dict) and "choices" in obj:
            for ch in obj.get("choices", []):
                d = ch.get("delta", {}) if isinstance(ch, dict) else {}
                if isinstance(d.get("content"), str):
                    parts.append(d["content"])
    return parts


# --------------------------------------------------------------------------- #
# Anthropic Messages API
# --------------------------------------------------------------------------- #

def _parse_anthropic_request(body: Any) -> ParsedContent:
    data = _json_or_none(body)
    if not isinstance(data, dict):
        return _parse_generic_request(body)
    acc: List[str] = []
    system = data.get("system")
    if isinstance(system, str):
        acc.append(system)
    else:
        _extract_content_text(system, acc)
    for msg in data.get("messages", []) or []:
        if isinstance(msg, dict):
            _extract_content_text(msg.get("content"), acc)
    return ParsedContent(
        text=_clip("\n".join(acc)),
        model=data.get("model"),
        parser="anthropic_messages",
    )


def _parse_anthropic_response(body: Any, content_type: str) -> ParsedContent:
    if "event-stream" in content_type:
        parts = _parse_sse_text(body)
        return ParsedContent(text=_clip("\n".join(parts)), parser="anthropic_messages")
    data = _json_or_none(body)
    if not isinstance(data, dict):
        return _parse_generic_response(body, content_type)
    acc: List[str] = []
    _extract_content_text(data.get("content"), acc)
    usage = data.get("usage", {}) if isinstance(data.get("usage"), dict) else {}
    return ParsedContent(
        text=_clip("\n".join(acc)),
        model=data.get("model"),
        tokens_in=_as_int(usage.get("input_tokens")),
        tokens_out=_as_int(usage.get("output_tokens")),
        parser="anthropic_messages",
    )


# --------------------------------------------------------------------------- #
# OpenAI Chat Completions API
# --------------------------------------------------------------------------- #

def _parse_openai_request(body: Any) -> ParsedContent:
    data = _json_or_none(body)
    if not isinstance(data, dict):
        return _parse_generic_request(body)
    acc: List[str] = []
    for msg in data.get("messages", []) or []:
        if isinstance(msg, dict):
            _extract_content_text(msg.get("content"), acc)
    if isinstance(data.get("input"), (str, list)):  # Responses API
        _extract_content_text(data.get("input"), acc)
    if isinstance(data.get("prompt"), str):  # legacy completions
        acc.append(data["prompt"])
    return ParsedContent(
        text=_clip("\n".join(acc)),
        model=data.get("model"),
        parser="openai_chat",
    )


def _parse_openai_response(body: Any, content_type: str) -> ParsedContent:
    if "event-stream" in content_type:
        parts = _parse_sse_text(body)
        return ParsedContent(text=_clip("\n".join(parts)), parser="openai_chat")
    data = _json_or_none(body)
    if not isinstance(data, dict):
        return _parse_generic_response(body, content_type)
    acc: List[str] = []
    for ch in data.get("choices", []) or []:
        if isinstance(ch, dict):
            msg = ch.get("message", {})
            if isinstance(msg, dict):
                _extract_content_text(msg.get("content"), acc)
            if isinstance(ch.get("text"), str):
                acc.append(ch["text"])
    usage = data.get("usage", {}) if isinstance(data.get("usage"), dict) else {}
    return ParsedContent(
        text=_clip("\n".join(acc)),
        model=data.get("model"),
        tokens_in=_as_int(usage.get("prompt_tokens")),
        tokens_out=_as_int(usage.get("completion_tokens")),
        parser="openai_chat",
    )


# --------------------------------------------------------------------------- #
# Generic fallback
# --------------------------------------------------------------------------- #

def _parse_generic_request(body: Any) -> ParsedContent:
    data = _json_or_none(body)
    if data is not None:
        acc: List[str] = []
        _walk_strings(data, acc)
        model = data.get("model") if isinstance(data, dict) else None
        return ParsedContent(text=_clip("\n".join(acc)), model=model, parser="generic")
    return ParsedContent(text=_clip(_to_text(body)), parser="generic")


def _parse_generic_response(body: Any, content_type: str) -> ParsedContent:
    if "event-stream" in content_type:
        return ParsedContent(text=_clip("\n".join(_parse_sse_text(body))), parser="generic")
    data = _json_or_none(body)
    if data is not None:
        acc: List[str] = []
        _walk_strings(data, acc)
        return ParsedContent(text=_clip("\n".join(acc)), parser="generic")
    if content_type.startswith("text/") or content_type == "":
        return ParsedContent(text=_clip(_to_text(body)), parser="generic")
    return ParsedContent(text="", parser="generic")  # бинарь/картинки не сканируем


# --------------------------------------------------------------------------- #
# Публичный интерфейс
# --------------------------------------------------------------------------- #

_REQUEST_PARSERS = {
    "anthropic_messages": _parse_anthropic_request,
    "openai_chat": _parse_openai_request,
    "generic": _parse_generic_request,
}


def parse_request(parser: str, content_type: str, body: Any) -> ParsedContent:
    fn = _REQUEST_PARSERS.get(parser, _parse_generic_request)
    try:
        return fn(body)
    except Exception:
        return _parse_generic_request(body)


def parse_response(parser: str, content_type: str, body: Any) -> ParsedContent:
    content_type = (content_type or "").lower()
    try:
        if parser == "anthropic_messages":
            return _parse_anthropic_response(body, content_type)
        if parser == "openai_chat":
            return _parse_openai_response(body, content_type)
        return _parse_generic_response(body, content_type)
    except Exception:
        return _parse_generic_response(body, content_type)
