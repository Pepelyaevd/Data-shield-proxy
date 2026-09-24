"""Типы данных DLP-движка.

Принцип минимизации данных (README → Analytics & Reporting): наружу из движка
уходит НЕ сырой секрет, а его маскированный сниппет + метаданные совпадения.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, List


class Severity:
    """Уровни серьёзности находки (строковые константы, а не Enum — для JSON)."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    _ORDER = {LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3}

    @classmethod
    def rank(cls, sev: str) -> int:
        return cls._ORDER.get(sev, 0)


class Verdict:
    """Вердикт DLP. В MVP работаем в alert-only: только ALLOW / ALERT."""

    ALLOW = "allow"
    ALERT = "alert"
    # Зарезервировано для fast-follow (enforcement), в MVP не выдаётся:
    REDACT = "redact"
    BLOCK = "block"


def mask(secret: str, keep: int = 4) -> str:
    """Маскирует значение для безопасного хранения/показа.

    Оставляет первые/последние `keep` символов, середину заменяет на '*'.
    Короткие значения маскируются целиком. Наружу сырой секрет не попадает.
    """
    if secret is None:
        return ""
    s = str(secret)
    if len(s) <= keep * 2:
        return "*" * len(s)
    return f"{s[:keep]}{'*' * max(4, len(s) - keep * 2)}{s[-keep:]}"


def fingerprint(secret: str) -> str:
    """Стабильный короткий хэш значения — для дедупликации без хранения сырых данных."""
    return hashlib.sha256(str(secret).encode("utf-8", "replace")).hexdigest()[:16]


@dataclass
class Finding:
    """Одно срабатывание детектора."""

    detector: str  # машинное имя детектора, напр. "aws_access_key"
    category: str  # "secret" | "pii" | "anomaly"
    severity: str  # см. Severity
    snippet: str  # МАСКИРОВАННЫЙ фрагмент (не сырой секрет)
    fp: str = ""  # fingerprint сырого значения (sha256[:16])
    count: int = 1  # сколько раз встретилось это же значение
    # Спан совпадения в отсканированном тексте — ВНУТРЕННЕЕ поле для
    # кросс-детекторной дедупликации в движке. Наружу (to_dict) не уходит.
    start: int = -1
    end: int = -1

    def to_dict(self) -> Dict[str, object]:
        # Явно перечисляем поля хранимой схемы: спаны — служебные, их не сохраняем.
        return {
            "detector": self.detector,
            "category": self.category,
            "severity": self.severity,
            "snippet": self.snippet,
            "fp": self.fp,
            "count": self.count,
        }


@dataclass
class DlpResult:
    """Итог сканирования одного текста."""

    verdict: str = Verdict.ALLOW
    findings: List[Finding] = field(default_factory=list)

    @property
    def max_severity(self) -> str:
        if not self.findings:
            return Severity.LOW
        return max((f.severity for f in self.findings), key=Severity.rank)

    def signatures(self) -> List[str]:
        """Список машинных имён сработавших детекторов (для быстрых отчётов)."""
        return sorted({f.detector for f in self.findings})

    def to_dict(self) -> Dict[str, object]:
        return {
            "verdict": self.verdict,
            "max_severity": self.max_severity,
            "findings": [f.to_dict() for f in self.findings],
        }
