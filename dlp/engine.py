"""DLP-движок: оркестрация детекторов, дедупликация, вычисление вердикта.

MVP-режим — alert-only: вердикт может быть только ALLOW или ALERT (никаких
block/redact). Порог enforcement выносится в fast-follow (см. ROADMAP).
"""

from __future__ import annotations

from typing import Callable, Dict, List, Optional

from dlp.detectors import ALL_DETECTORS, detector_priority
from dlp.types import DlpResult, Finding, Verdict


class DlpEngine:
    def __init__(
        self,
        detectors: Optional[List[Callable[[str], List[Finding]]]] = None,
        enforce: bool = False,
    ) -> None:
        # enforce=False → alert-only (по умолчанию для MVP).
        self.detectors = detectors if detectors is not None else list(ALL_DETECTORS)
        self.enforce = enforce

    def scan(self, text: str) -> DlpResult:
        if not text:
            return DlpResult(verdict=Verdict.ALLOW, findings=[])

        raw: List[Finding] = []
        for detector in self.detectors:
            try:
                raw.extend(detector(text))
            except Exception:  # один детектор не должен ронять весь скан
                continue

        findings = self._dedupe(raw)
        findings = self._suppress_overlaps(findings)
        verdict = Verdict.ALERT if findings else Verdict.ALLOW
        return DlpResult(verdict=verdict, findings=findings)

    @staticmethod
    def _dedupe(findings: List[Finding]) -> List[Finding]:
        """Схлопывает повторы одного значения одним детектором, копит count."""
        merged: Dict[tuple, Finding] = {}
        for f in findings:
            key = (f.detector, f.fp)
            if key in merged:
                merged[key].count += 1
            else:
                merged[key] = f
        return list(merged.values())

    @staticmethod
    def _suppress_overlaps(findings: List[Finding]) -> List[Finding]:
        """Кросс-детекторная дедупликация по спанам.

        Если спан «широкой» находки (high_entropy_string, credential_assignment)
        пересекается со спаном более специфичной (сигнатура/PII), широкая
        отбрасывается — тот же секрет не даёт дублей в рамках одного скана.
        Находки без спанов (start<0) не участвуют в подавлении.
        """
        located = [f for f in findings if f.start >= 0 and f.end > f.start]
        if len(located) < 2:
            return findings

        drop: set = set()
        for i, a in enumerate(located):
            for b in located[i + 1:]:
                if a.start < b.end and b.start < a.end:  # спаны пересекаются
                    pa, pb = detector_priority(a.detector), detector_priority(b.detector)
                    if pa == pb:
                        continue  # одинаковая специфичность — оба сохраняем
                    loser = b if pa > pb else a
                    drop.add(id(loser))
        if not drop:
            return findings
        return [f for f in findings if id(f) not in drop]


# Удобный модульный вход для разовых сканов.
_DEFAULT = DlpEngine()


def scan(text: str) -> DlpResult:
    return _DEFAULT.scan(text)
