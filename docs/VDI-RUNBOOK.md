# VDI Runbook — тестовый стенд Data-Shield-Proxy

Операционная памятка по тестовому серверу, где развёрнут прокси (server-side), а
клиент (агент + лаунчер) — на рабочей машине. Общая архитектура распределённого
режима — в [QUICKSTART.md](QUICKSTART.md#распределённый-режим-прокси-на-отдельном-хосте).

> ⚠️ Тестовый стенд. Секрет-ворота и открытый порт — MVP-заглушки. Для прода:
> сменить секрет, ограничить порт по IP, поднять реальную аутентификацию.

---

## Доступ (данные — вне git)

Все чувствительные данные стенда (IP, пользователь, ключ) вынесены в
**`secrets/vdi.env`** (папка `secrets/` в `.gitignore` — в GitHub не попадает).
Шаблон — [`vdi.env.example`](../vdi.env.example):

```bash
cp vdi.env.example secrets/vdi.env   # затем впиши VDI_HOST/VDI_USER/VDI_KEY
```

Загрузить доступ и завести хелпер `vdi` (из корня репозитория):
```bash
set -a; source secrets/vdi.env; set +a
vdi(){ ssh -i "$VDI_KEY" -o BatchMode=yes "$VDI_USER@$VDI_HOST" "$@"; }
vdi 'echo OK: $(hostname)'
```

| Параметр | Где |
|---|---|
| Хост / пользователь | `secrets/vdi.env` → `VDI_HOST`, `VDI_USER` |
| SSH-ключ | `secrets/dsp_vdi_ed25519` (в `.gitignore`) |
| Пароль root | у владельца; **сменить после теста** |

> Если ключ потерян — зайти паролем и повторно добавить публичный ключ
> `secrets/dsp_vdi_ed25519.pub` в `~/.ssh/authorized_keys` на сервере.

---

## Что развёрнуто

| Компонент | Значение |
|---|---|
| Контейнер | `dsp-proxy` (образ `mitmproxy/mitmproxy:latest`) |
| Порт | `8080` (публично, `0.0.0.0`) |
| Секрет-ворота | `DSP_PROXY_SECRET` (см. `.dsp.env` / `secrets/vdi.env`) |
| Код проекта | `/root/dsp` (`proxy/ dlp/ catalog/ storage/ report/`) |
| CA (issuing) | `/root/dsp/mitmproxy-ca/mitmproxy-ca-cert.pem` |
| События (SQLite) | `/root/dsp/data/events.db` |
| VPN на том же хосте | контейнер `amnezia-awg2` (UDP 30048) — **не трогать** |

Команда запуска контейнера (для пересоздания):
```bash
vdi 'docker run -d --name dsp-proxy --restart unless-stopped \
  -e DSP_DB_PATH=/app/data/events.db -e DSP_PROXY_SECRET=123456 \
  -v /root/dsp:/app -w /app \
  -v /root/dsp/mitmproxy-ca:/home/mitmproxy/.mitmproxy \
  -p 8080:8080 mitmproxy/mitmproxy:latest \
  mitmdump --listen-host 0.0.0.0 -p 8080 -s /app/proxy/addon.py \
  --set stream_large_bodies=5m --set connection_strategy=lazy --set block_global=false'
```
> `block_global=false` обязателен — иначе mitmproxy режет коннекты с публичных IP.

---

## Операции

```bash
# статус / логи (DLP-алерты, отказы 407)
vdi 'docker ps --filter name=dsp-proxy --format "{{.Status}} {{.Ports}}"'
vdi 'docker logs --tail 50 dsp-proxy'
vdi 'docker logs dsp-proxy 2>&1 | grep -iE "DLP alert|Отклонён"'

# перезапуск
vdi 'docker restart dsp-proxy'

# обновить код на сервере (с рабочей машины, из корня репо):
tar czf - --exclude=__pycache__ proxy dlp catalog storage report \
  | ssh -i "$VDI_KEY" "$VDI_USER@$VDI_HOST" 'tar xzf - -C /root/dsp'
vdi 'docker restart dsp-proxy'   # подхватить изменения addon/конфига
```

---

## Отчёты (server-side)

```bash
vdi 'cd /root/dsp && python3 -m report.cli summary'
vdi 'cd /root/dsp && python3 -m report.cli usage'
vdi 'cd /root/dsp && python3 -m report.cli incidents'

# HTML-отчёт: сгенерировать на сервере и забрать
vdi 'cd /root/dsp && python3 -m report.cli html --out report_out/report.html'
scp -i "$VDI_KEY" "$VDI_USER@$VDI_HOST":/root/dsp/report_out/report.html \
  report_out/vdi-report.html
```

---

## CA и клиент

CA с сервера забирается на рабочую машину в `deploy/vdi-ca.pem` (gitignored):
```bash
scp -i "$VDI_KEY" "$VDI_USER@$VDI_HOST":/root/dsp/mitmproxy-ca/mitmproxy-ca-cert.pem \
  deploy/vdi-ca.pem
```

Клиентский конфиг `.dsp.env` (gitignored) указывает на этот сервер
(`DSP_PROXY`/`DSP_PROXY_SECRET`/`DSP_CA`). Запуск агента:
`python3 launcher/launch.py -- claude` · UI: `make webui`.

Быстрая проверка тракта без агента:
```bash
python3 launcher/launch.py -- curl -sS https://api.anthropic.com/v1/messages \
  -H 'content-type: application/json' \
  -d '{"model":"claude-sonnet-5","messages":[{"role":"user","content":"AKIAIOSFODNN7EXAMPLE"}]}'
```

---

## Безопасность / TODO стенда

- [ ] Сменить root-пароль сервера.
- [ ] Ограничить порт 8080 списком IP клиентов (через `DOCKER-USER`, не трогая
      правила Amnezia/WireGuard), либо вернуть прокси за SSH-туннель.
- [ ] Заменить секрет-ворота на реальную аутентификацию (SSO/mTLS).
- [ ] `secrets/` (ключ, `vdi.env`) — только локально, не коммитить.
