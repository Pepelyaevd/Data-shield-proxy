"""DLP Engine — детектирование чувствительных данных (alert-only в MVP).

См. README.md → DLP Engine и docs/ROADMAP.md → п.5.
"""

from dlp.types import Finding, DlpResult, Severity, Verdict
from dlp.engine import DlpEngine, scan

__all__ = [
    "Finding",
    "DlpResult",
    "Severity",
    "Verdict",
    "DlpEngine",
    "scan",
]
