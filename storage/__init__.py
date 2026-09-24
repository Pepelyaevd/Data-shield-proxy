"""Хранилище событий (SQLite для MVP).

Событие содержит МЕТАДАННЫЕ и маскированные сигнатуры — без сырого чувствительного
содержимого (README → минимизация данных).
"""

from storage.db import EventStore, Event

__all__ = ["EventStore", "Event"]
