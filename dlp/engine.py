"""DLP-движок: оркестрация детекторов, дедупликация, вычисление вердикта.

MVP-режим — alert-only: вердикт может быть только ALLOW или ALERT (никаких
block/redact). Порог enforcement выносится в fast-follow (см. ROADMAP).
"""

from __future__ import annotations

from typing import Callable, Dict, List, Optional

from dlp.detectors import ALL_DETECTORS
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


# Удобный модульный вход для разовых сканов.
_DEFAULT = DlpEngine()


def scan(text: str) -> DlpResult:
    return _DEFAULT.scan(text)
