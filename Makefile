# Data-Shield-Proxy — задачи разработки и запуска MVP.
.DEFAULT_GOAL := help
SHELL := /bin/bash
PY ?= python3
VENV ?= .venv

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

.PHONY: proxy-up
proxy-up: ## поднять прокси (docker compose)
	cd deploy && docker compose up -d proxy
	@echo "Прокси на :8080. CA сгенерируется в ~/.mitmproxy — затем: make ca-install"

.PHONY: proxy-logs
proxy-logs: ## смотреть логи прокси (DLP-алерты)
	cd deploy && docker compose logs -f proxy

.PHONY: proxy-down
proxy-down: ## остановить прокси
	cd deploy && docker compose down

.PHONY: ca-install
ca-install: ## установить CA mitmproxy в доверенное хранилище
	deploy/install-ca.sh

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
