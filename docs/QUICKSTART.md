# Быстрый старт (MVP)

Локальный запуск сквозного core-loop: запуск агента через прокси → TLS-инспекция
→ извлечение промпта → DLP-детект → событие с атрибуцией → отчёт.

Архитектура — в [../README.md](../README.md), план — в [ROADMAP.md](ROADMAP.md).

> Разворачивать только на **корпоративных устройствах уведомлённых сотрудников**
> (README, раздел 0). Установка CA меняет доверие TLS — это делается в рамках
> корпоративной политики, не тайно.

---

## 0. Проверка без прокси и Docker (быстро)

Ядро (детекторы, парсеры, хранилище, отчёт) работает на чистой stdlib:

```bash
make test        # 39 юнит-тестов (unittest, установка не нужна)
make demo        # демонстрация DoD: посаженные секреты → инциденты в отчёте
```

`make demo` прогоняет реальные модули `catalog → parsers → dlp → storage → report`
без mitmproxy и печатает частоту по пользователям и список DLP-инцидентов.

---

## 1. Поднять прокси (TLS-инспекция)

Нужен Docker (mitmproxy идёт в базовом образе, ставить ничего не надо):

```bash
make proxy-up            # прокси на 127.0.0.1:8080
make proxy-logs          # смотреть DLP-алерты в реальном времени
```

При первом запуске mitmproxy генерирует самоподписанный CA в `~/.mitmproxy/`
(закрывает требование 2 на уровне MVP). События пишутся в `./data/events.db`.

## 2. Установить корпоративный CA

```bash
make ca-install          # macOS/Linux: добавляет CA в системное хранилище (sudo)
deploy/install-ca.sh --print   # только путь к CA и подсказка по env-переменным
```

## 3. Запустить агента через лаунчер

Перехватывается **только трафик запущенного агента** (адресный прокси).

```bash
# CLI-агент (Claude Code), атрибуция пользователю alice:
python3 launcher/launch.py --profile cli --user alice --agent claude-code -- claude

# Проверка на curl (посадим секрет в запрос):
python3 launcher/launch.py --profile cli --user alice -- \
  curl -s https://api.anthropic.com/v1/messages \
  -H 'content-type: application/json' \
  -d '{"model":"claude-sonnet-5","messages":[{"role":"user","content":"ключ AKIAIOSFODNN7EXAMPLE"}]}'

# desktop-агент (флаг --proxy-server добавляется автоматически):
python3 launcher/launch.py --profile desktop --user carol --agent chatgpt-desktop -- \
  /Applications/ChatGPT.app/Contents/MacOS/ChatGPT
```

`--dry-run` показывает, что будет запущено, ничего не выполняя.

Идентичность передаётся через userinfo прокси (`user:agent@host`) → заголовок
`Proxy-Authorization` при CONNECT → addon атрибутирует событие пользователю.

## 4. Отчёты

```bash
make report                      # краткая сводка
python3 -m report.cli usage      # частота по пользователям и агентам
python3 -m report.cli incidents --user alice
make report-html                 # → report_out/report.html
```

Отчёт по данным из Docker (тот же `./data/events.db`, он bind-mount):

```bash
cd deploy && docker compose run --rm report summary
# если Compose v2 не установлен — standalone-бинарь: docker-compose run --rm report summary
```

> `make`-цели (`proxy-up`/`proxy-logs`/`proxy-down`) сами определяют, что
> доступно — плагин `docker compose` или standalone `docker-compose`.

---

## Распределённый режим (прокси на отдельном хосте)

Целевая топология: прокси + хранилище + отчёты на сервере, агент + лаунчер на
машине сотрудника. Прокси открыт по адресу и защищён общим секретом-воротами
(MVP; полноценные пользователи/токены/админка — после MVP).

**Сервер** (Docker):
```bash
docker run -d --name dsp-proxy --restart unless-stopped \
  -e DSP_DB_PATH=/app/data/events.db -e DSP_PROXY_SECRET=123456 \
  -v /root/dsp:/app -w /app \
  -v /root/dsp/mitmproxy-ca:/home/mitmproxy/.mitmproxy \
  -p 8080:8080 mitmproxy/mitmproxy:latest \
  mitmdump --listen-host 0.0.0.0 -p 8080 -s /app/proxy/addon.py \
  --set stream_large_bodies=5m --set connection_strategy=lazy --set block_global=false
```
> `block_global=false` нужен, иначе mitmproxy режет подключения с публичных IP.
> Открытый прокси защищён `DSP_PROXY_SECRET`; для прод-безопасности ограничьте
> порт 8080 на фаерволе списком IP клиентов.

**Клиент.** Конфиг провижинится один раз (в проде — через MDM/установщик),
после чего команда запуска — одна. Лаунчер сам подхватывает `DSP_*` из файла
`.dsp.env` (или `~/.dsp.conf`, или `$DSP_CONFIG`):

```bash
# провижининг один раз (файл с секретом, не коммитится):
cat > .dsp.env <<'CFG'
DSP_PROXY=http://<server-ip>:8080
DSP_PROXY_SECRET=123456
DSP_CA=/path/to/mitmproxy-ca-cert.pem
CFG
```

Дальше сотрудник просто запускает агента через лаунчер — прокси, секрет, CA и
идентичность (OS-логин) подхватываются автоматически:

```bash
python3 launcher/launch.py -- claude
```

Клиент подключается как `http://<user>:<secret>@server:8080`: `user` (OS-логин) →
атрибуция, `secret` → ворота. Без верного секрета прокси отвечает `407`.

## Подключить нового агента

1. **Профиль запуска** — добавить запись в [../launcher/profiles.json](../launcher/profiles.json)
   (какие env/флаги проставить).
2. **Каталог** — добавить провайдера (домены → парсер) в
   [../catalog/catalog.py](../catalog/catalog.py).
3. **Парсер контента** (опционально) — если у API своя схема, добавить парсер в
   [../catalog/parsers.py](../catalog/parsers.py); иначе сработает generic-fallback.

## Полезное

| Действие | Команда |
|---|---|
| Тесты | `make test` |
| Демонстрация DoD | `make demo` |
| Поднять/погасить прокси | `make proxy-up` / `make proxy-down` |
| Логи прокси | `make proxy-logs` |
| Установить CA | `make ca-install` |
| Сводка / HTML-отчёт | `make report` / `make report-html` |

## Известные ограничения MVP

- **desktop-профиль**: `--proxy-server` не поддерживает userinfo → атрибуция
  по IP/дефолту (не по имени пользователя). CLI-профиль атрибутирует точно.
- **Certificate pinning**: нативные агенты с пиннингом не поддаются MITM
  (см. README → Риски). Браузеры и CLI на системном/Node trust store работают.
- **enforcement**: MVP работает в `alert-only` (`DSP_ENFORCE=false`), трафик не
  блокируется. Блокировка/редакция — fast-follow.
