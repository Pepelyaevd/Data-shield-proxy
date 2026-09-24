# Data-Shield-Proxy — задачи разработки и запуска MVP.
.DEFAULT_GOAL := help
SHELL := /bin/bash
PY ?= python3
VENV ?= .venv

# Автоопределение Compose: плагин `docker compose` (v2) или standalone `docker-compose`.
COMPOSE := $(shell if docker compose version >/dev/null 2>&1; then echo "docker compose"; \
	elif command -v docker-compose >/dev/null 2>&1; then echo "docker-compose"; \
	else echo "docker compose"; fi)

.PHONY: help
help: ## показать список команд
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	 awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.PHONY: venv
venv: ## создать venv и поставить зависимости (нужен Python 3.10+ для mitmproxy)
	$(PY) -m venv $(VENV)
	$(VENV)/bin/pip install -U pip
	$(VENV)/bin/pip install -r requirements-dev.txt

.PHONY: test
test: ## прогнать тесты (stdlib unittest, без установки)
	$(PY) -m unittest discover -s tests -v

.PHONY: demo
demo: ## сквозная демонстрация DoD без mitmproxy (pipeline + отчёт)
	$(PY) scripts/demo_e2e.py

.PHONY: webui
webui: ## лаунчер в браузере (надёжно): кнопка «Открыть Claude (под защитой)»
	$(PY) launcher/webui.py

.PHONY: ui
ui: ## GUI-лаунчер на Tkinter (запасной; на системном Tk 8.5/macOS может не рисовать)
	$(PY) launcher/ui.py

.PHONY: proxy-up
proxy-up: ## поднять прокси (docker compose)
	cd deploy && $(COMPOSE) up -d proxy
	@echo "Прокси на :8080. CA сгенерируется в ~/.mitmproxy — затем: make ca-install"

.PHONY: proxy-logs
proxy-logs: ## смотреть логи прокси (DLP-алерты)
	cd deploy && $(COMPOSE) logs -f proxy

.PHONY: proxy-down
proxy-down: ## остановить прокси
	cd deploy && $(COMPOSE) down

.PHONY: ca-install
ca-install: ## установить CA mitmproxy в доверенное хранилище
	deploy/install-ca.sh

.PHONY: admin
admin: ## Control Plane — админский Web UI (отчёты/инциденты/уровни)
	$(PY) -m controlplane.server

.PHONY: report
report: ## краткая сводка по событиям
	$(PY) -m report.cli summary

.PHONY: report-html
report-html: ## сгенерировать HTML-отчёт в report_out/report.html
	$(PY) -m report.cli html --out report_out/report.html

.PHONY: clean
clean: ## удалить артефакты (venv, кэш, локальную БД)
	rm -rf $(VENV) .pytest_cache report_out
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
