-- Схема хранилища событий Data-Shield-Proxy (MVP, SQLite).
-- Хранятся МЕТАДАННЫЕ + маскированные сигнатуры, НЕ сырое содержимое промптов.

CREATE TABLE IF NOT EXISTS events (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    ts                 TEXT    NOT NULL,           -- ISO-8601 UTC
    user               TEXT,                       -- атрибуция пользователю
    device             TEXT,                       -- устройство/хост
    agent              TEXT,                       -- машинное имя агента (claude-code, …)
    provider           TEXT,                       -- провайдер (anthropic, openai, …)
    model              TEXT,                       -- модель, если извлечена
    destination        TEXT,                       -- хост назначения
    direction          TEXT,                       -- request | response
    tokens_in          INTEGER,
    tokens_out         INTEGER,
    bytes              INTEGER,                     -- размер тела
    verdict            TEXT    NOT NULL DEFAULT 'allow',  -- allow | alert
    matched_signatures TEXT    NOT NULL DEFAULT '[]'      -- JSON: [{detector,category,severity,snippet,fp,count}]
);

CREATE INDEX IF NOT EXISTS idx_events_ts       ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_user     ON events(user);
CREATE INDEX IF NOT EXISTS idx_events_provider ON events(provider);
CREATE INDEX IF NOT EXISTS idx_events_verdict  ON events(verdict);
