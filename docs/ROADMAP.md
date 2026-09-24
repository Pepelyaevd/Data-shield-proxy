# План реализации (MVP-first)

Детальный план поставки. Архитектура — в [../README.md](../README.md).

## Принципы

- **MVP-first** — сначала тонкий вертикальный срез, доказывающий сквозной
  core-loop; ширина и надёжность наращиваются итеративно.
- **Alert-only на старте** — не блокируем трафик, только логируем и флагаем
  инциденты (снижаем false-positive и трение с разработчиками).
- **Адресный перехват** — инспектируем только трафик управляемых агентов, не всё
  устройство.
- **egress-lock (защита от обхода) — вне MVP**, отложено осознанно (см. [M8](#m8--egress-lock-защита-от-обхода)).

---

## MVP

### Цель
Доказать сквозной core-loop на одном-двух агентах:

> запуск агента с proxy-параметрами → TLS-инспекция → извлечение промпта →
> DLP-детект → событие с атрибуцией пользователю → отчёт по частоте и инцидентам.

### Что валидируем (главные риски)
1. Агент реально ходит через прокси, и мы расшифровываем его TLS (доверие к CA,
   агент уважает proxy-параметры).
2. Извлекаем содержимое промпта и ловим чувствительные сигнатуры.
3. Атрибутируем пользователю и строим отчёт (требование 5).

### В scope MVP
- **Агенты (1–2)**: Claude Code CLI + условный desktop (Chromium/Electron через
  `--proxy-server`).
- **Лаунчер**: wrapper-скрипт — проставляет `HTTPS_PROXY`/`NODE_EXTRA_CA_CERTS`
  (CLI) либо `--proxy-server` (desktop) и identity; установка CA — ручная/скриптом.
- **Прокси**: `mitmproxy` + addon. CA — встроенный самоподписанный CA mitmproxy
  (закрывает требование 2 на уровне MVP).
- **Парсер контента**: Anthropic Messages API + generic JSON-fallback.
- **DLP (alert-only)**: regex (секреты, API-ключи, PII), энтропийный анализ, Luhn.
- **Хранилище**: SQLite. Событие: `ts, user, agent, provider, model, dest,
  tokens, verdict, matched_signatures[]`.
- **Отчётность**: CLI-отчёт (частота по пользователям + список инцидентов); опц.
  минимальная read-only HTML-страница.
- **Инфра**: `docker-compose` (proxy + отчётность) + launcher-скрипт для клиента.

Покрытие требований в MVP: **3** (полностью), **2/4/5** (базово), **1** —
конфиг-файлы + CLI-отчёт (минимально).

### Вне scope MVP (fast-follow)
egress-lock · step-ca/HSM/ротация CA · блокировка и редакция · Kafka/ClickHouse/
OpenSearch · Envoy/HA · полноценный Web UI + Policy Engine (OPA) · MDM-
автоматизация · ML-классификаторы и Exact Data Match · широкий набор провайдеров.

### Definition of Done (MVP)
Запускаем агента через wrapper → отправляем промпт с «посаженным» секретом →
прокси расшифровал, addon извлёк текст, DLP пометил инцидент → событие записано в
SQLite с `user`+`agent` → CLI-отчёт показывает частоту по пользователю и этот
инцидент. Приложен короткий README по запуску.

### Пункты реализации

1. **Каркас проекта**
   - [x] Структура репо: `proxy/`, `dlp/`, `catalog/`, `launcher/`, `storage/`,
     `report/`, `deploy/`.
   - [x] Dev-окружение (Python venv, `mitmproxy`), Makefile/скрипты запуска.

2. **CA и доверие**
   - [x] Встроенный самоподписанный CA `mitmproxy` (генерируется при старте прокси).
   - [x] Скрипт установки CA в системный trust store + `NODE_EXTRA_CA_CERTS`
     ([deploy/install-ca.sh](../deploy/install-ca.sh)).

3. **Прокси с TLS-инспекцией**
   - [x] Поднять `mitmproxy` в forward-режиме ([deploy/docker-compose.yml](../deploy/docker-compose.yml)).
   - [x] Addon: хуки request/response/error, метаданные (dest, SNI, размер)
     ([proxy/addon.py](../proxy/addon.py)).

4. **Каталог и парсер контента**
   - [x] Мини-каталог провайдеров (домены → провайдер), стартово Anthropic.
   - [x] Парсер тела Anthropic Messages → текст промпта (+ ответ, токены, SSE).
   - [x] Generic JSON-fallback + OpenAI-парсер для прочих.

5. **DLP-детекторы (alert-only)**
   - [x] Regex-секреты: AWS/GCP/GitHub/Slack/Stripe/OpenAI/Anthropic-ключи,
     private key, JWT, connection strings, присваивания кредов.
   - [x] PII: email, телефоны, карты (Luhn), ИНН/СНИЛС (РФ, с валидацией).
   - [x] Энтропийный детектор high-entropy строк.
   - [x] Результат: `verdict` + `matched_signatures[]`, без блокировки; маскирование.

6. **Идентичность пользователя**
   - [x] Лаунчер проставляет identity (userinfo прокси → `Proxy-Authorization`),
     addon читает; поддержка заголовков `X-DSP-*` (gateway-режим).
   - [x] Fallback на OS-пользователя (в лаунчере) / дефолт (в addon).

7. **Хранилище событий (SQLite)**
   - [x] Схема `events` (ts, user, agent, provider, model, dest, tokens, verdict,
     signatures) — [storage/schema.sql](../storage/schema.sql).
   - [x] Запись событий из addon (одно событие на обмен request/response).

8. **Лаунчер (wrapper)**
   - [x] Профиль CLI: env `HTTPS_PROXY`/`NODE_EXTRA_CA_CERTS`/identity → запуск агента.
   - [x] Профиль desktop: флаг `--proxy-server=…`.
   - [x] Инструкция подключения нового агента ([docs/QUICKSTART.md](QUICKSTART.md)).

9. **Отчётность (CLI)**
   - [x] Частота использования по пользователям/агентам.
   - [x] Список DLP-инцидентов.
   - [x] Read-only HTML-страница ([report/html.py](../report/html.py)).

10. **Инфраструктура запуска**
    - [x] `docker-compose` (proxy + report).
    - [x] README по локальному запуску ([docs/QUICKSTART.md](QUICKSTART.md)).

11. **Проверка DoD**
    - [x] Сквозной сценарий: промпт с посаженным секретом → инцидент в отчёте с
      атрибуцией пользователю (`make demo`, `tests/test_e2e.py`).
    - [x] Тестовые фикстуры ([tests/fixtures/sample_prompts.json](../tests/fixtures/sample_prompts.json)).

> **Статус.** Ядро (catalog · parsers · dlp · storage · report · launcher · addon)
> реализовано и покрыто 39 юнит-тестами; core-loop подтверждён `make demo`.
> Живой TLS-MITM через mitmproxy запускается `make proxy-up` (требует Docker) —
> транспортное звено не прогонялось в dev-окружении без Docker/mitmproxy.

### Оценка
~2–3 недели. Ядро MVP реализовано; осталась живая приёмка через mitmproxy+Docker
на реальном агенте.

---

## Дальнейшее развитие (кратко)

- **Детекторы/парсеры вглубь**: больше провайдеров (OpenAI, Google…), расширенные
  сигнатуры, тюнинг false-positive.
- **Стор и отчётность**: Postgres/ClickHouse + шина событий, дашборды, экспорт.
- **Полноценный PKI**: `step-ca` (Root+Issuing), HSM, ротация.
- **Плоскость управления**: Web UI, Policy Engine (OPA), RBAC/SSO, аудит.
- **Enforcement**: поэтапные `block`/`redact`, процесс апелляций.
- **Дистрибуция**: Managed Launcher через MDM (Jamf/Intune/GPO).
- **Масштаб/harden**: Envoy, HA, пентест, DR.
- **egress-lock**: защита от обхода (к AI-доменам только через прокси).
