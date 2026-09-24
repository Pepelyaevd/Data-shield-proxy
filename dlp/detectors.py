"""Детекторы чувствительных данных (regex + валидаторы + энтропия).

Каждый детектор — функция text -> list[Finding]. Движок (engine.py) их оркестрирует.
Все значения маскируются перед возвратом (types.mask), сырьё наружу не уходит.

Покрытие MVP (docs/ROADMAP.md, п.5):
  - секреты: AWS/GCP-ключи, private keys, JWT, connection strings, токены;
  - PII: email, телефоны, карты (Luhn), ИНН/СНИЛС (РФ);
  - энтропийный детектор high-entropy строк.
"""

from __future__ import annotations

import math
import re
from typing import Callable, List

from dlp.types import Finding, Severity, mask, fingerprint


# --------------------------------------------------------------------------- #
# Вспомогательное
# --------------------------------------------------------------------------- #

def _finding(detector: str, category: str, severity: str, raw: str) -> Finding:
    return Finding(
        detector=detector,
        category=category,
        severity=severity,
        snippet=mask(raw),
        fp=fingerprint(raw),
    )


def shannon_entropy(s: str) -> float:
    """Энтропия Шеннона (бит/символ)."""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def luhn_valid(number: str) -> bool:
    """Проверка контрольной суммы по алгоритму Луна (карты)."""
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def inn_valid(inn: str) -> bool:
    """Валидация российского ИНН (10 или 12 цифр) по контрольным разрядам."""
    if not inn.isdigit():
        return False

    def _csum(digs, coeffs):
        return sum(d * c for d, c in zip(digs, coeffs)) % 11 % 10

    d = [int(c) for c in inn]
    if len(inn) == 10:
        return _csum(d, [2, 4, 10, 3, 5, 9, 4, 6, 8]) == d[9]
    if len(inn) == 12:
        n11 = _csum(d, [7, 2, 4, 10, 3, 5, 9, 4, 6, 8])
        n12 = _csum(d, [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8])
        return n11 == d[10] and n12 == d[11]
    return False


def snils_valid(snils: str) -> bool:
    """Валидация российского СНИЛС (11 цифр) по контрольному числу."""
    digits = re.sub(r"\D", "", snils)
    if len(digits) != 11:
        return False
    body = [int(c) for c in digits[:9]]
    control = int(digits[9:])
    s = sum(d * (9 - i) for i, d in enumerate(body))
    if s < 100:
        check = s
    elif s in (100, 101):
        check = 0
    else:
        check = s % 101
        if check in (100, 101):
            check = 0
    return check == control


# --------------------------------------------------------------------------- #
# Секреты — простые regex-паттерны (detector, category, severity, pattern)
# --------------------------------------------------------------------------- #

_SECRET_PATTERNS = [
    ("aws_access_key", Severity.CRITICAL, r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{16}\b"),
    ("gcp_api_key", Severity.HIGH, r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    ("google_oauth_token", Severity.HIGH, r"\bya29\.[0-9A-Za-z\-_]+\b"),
    ("github_token", Severity.CRITICAL, r"\bgh[posru]_[0-9A-Za-z]{36,255}\b"),
    ("slack_token", Severity.HIGH, r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b"),
    ("stripe_key", Severity.CRITICAL, r"\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}\b"),
    ("openai_key", Severity.CRITICAL, r"\bsk-(?:proj-)?[0-9A-Za-z_\-]{20,}\b"),
    ("anthropic_key", Severity.CRITICAL, r"\bsk-ant-[0-9A-Za-z_\-]{20,}\b"),
    ("private_key", Severity.CRITICAL,
     r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"),
    ("jwt", Severity.MEDIUM,
     r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    ("connection_string", Severity.HIGH,
     r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql)://"
     r"[^\s:@/]+:[^\s:@/]+@[^\s/]+"),
]

# Присваивания вида api_key = "....": ключ и минимально длинное значение.
_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret[_-]?key|secret|access[_-]?token|auth[_-]?token|"
    r"token|password|passwd|pwd|client[_-]?secret)\b\s*[:=]\s*"
    r"['\"]?([^\s'\"]{12,})['\"]?"
)


def detect_secrets(text: str) -> List[Finding]:
    out: List[Finding] = []
    for detector, severity, pattern in _SECRET_PATTERNS:
        for m in re.finditer(pattern, text):
            out.append(_finding(detector, "secret", severity, m.group(0)))
    for m in _ASSIGNMENT_RE.finditer(text):
        value = m.group(2)
        # не дублируем то, что уже поймали более специфичные детекторы
        out.append(_finding("credential_assignment", "secret", Severity.MEDIUM, value))
    return out


# --------------------------------------------------------------------------- #
# PII
# --------------------------------------------------------------------------- #

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_PHONE_RE = re.compile(
    r"(?<![\w.])(?:\+?\d{1,3}[\s.\-]?)?(?:\(\d{2,4}\)[\s.\-]?)?"
    r"\d{2,4}[\s.\-]?\d{2,4}[\s.\-]?\d{2,4}(?![\w.])"
)
_CARD_RE = re.compile(r"\b(?:\d[ \-]?){13,19}\b")
_INN_RE = re.compile(r"(?<!\d)(\d{12}|\d{10})(?!\d)")
_SNILS_RE = re.compile(r"(?<!\d)\d{3}[\s\-]?\d{3}[\s\-]?\d{3}[\s\-]?\d{2}(?!\d)")


def detect_pii(text: str) -> List[Finding]:
    out: List[Finding] = []
    claimed: List[tuple] = []  # спаны (start, end), уже занятые card/inn/snils

    for m in _EMAIL_RE.finditer(text):
        out.append(_finding("email", "pii", Severity.LOW, m.group(0)))

    for m in _CARD_RE.finditer(text):
        raw = m.group(0)
        if luhn_valid(raw):
            claimed.append(m.span())
            out.append(_finding("credit_card", "pii", Severity.HIGH, raw))

    for m in _INN_RE.finditer(text):
        raw = m.group(1)
        if inn_valid(raw):
            claimed.append(m.span(1))
            out.append(_finding("ru_inn", "pii", Severity.MEDIUM, raw))

    for m in _SNILS_RE.finditer(text):
        raw = m.group(0)
        if snils_valid(raw):
            claimed.append(m.span())
            out.append(_finding("ru_snils", "pii", Severity.MEDIUM, raw))

    # Телефоны — самый шумный детектор: требуем разделители/скобки/'+',
    # чтобы не ловить произвольные числовые последовательности; и пропускаем
    # спаны, уже опознанные как карта/ИНН/СНИЛС (устраняем пересечения).
    for m in _PHONE_RE.finditer(text):
        raw = m.group(0)
        digits = re.sub(r"\D", "", raw)
        if not (10 <= len(digits) <= 15):
            continue
        if not re.search(r"[\s.\-()]|^\+", raw):
            continue
        if _overlaps(m.span(), claimed):
            continue
        out.append(_finding("phone", "pii", Severity.LOW, raw))

    return out


def _overlaps(span: tuple, claimed: List[tuple]) -> bool:
    s, e = span
    for cs, ce in claimed:
        if s < ce and cs < e:  # пересечение диапазонов
            return True
    return False


# --------------------------------------------------------------------------- #
# Энтропийный детектор — ловит секреты, не покрытые сигнатурами
# --------------------------------------------------------------------------- #

_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")
# Что похоже на структурный шум, а не на секрет (снижаем false-positive):
_LOOKS_LIKE_WORD_RE = re.compile(r"^[A-Za-z][a-z]+$")


def detect_entropy(text: str, min_entropy: float = 4.0, min_len: int = 20) -> List[Finding]:
    out: List[Finding] = []
    seen = set()
    for m in _TOKEN_RE.finditer(text):
        tok = m.group(0)
        if len(tok) < min_len or _LOOKS_LIKE_WORD_RE.match(tok):
            continue
        fp = fingerprint(tok)
        if fp in seen:
            continue
        if shannon_entropy(tok) >= min_entropy:
            seen.add(fp)
            out.append(_finding("high_entropy_string", "secret", Severity.MEDIUM, tok))
    return out


# Порядок применения детекторов в движке.
ALL_DETECTORS: List[Callable[[str], List[Finding]]] = [
    detect_secrets,
    detect_pii,
    detect_entropy,
]
