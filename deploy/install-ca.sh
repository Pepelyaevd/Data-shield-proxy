#!/usr/bin/env bash
# Установка корпоративного CA (mitmproxy) в доверенное хранилище устройства.
#
# В MVP используется встроенный самоподписанный CA mitmproxy (закрывает
# требование 2 на уровне пилота). CA генерируется при первом запуске прокси
# и лежит в ~/.mitmproxy/ (см. deploy/docker-compose.yml).
#
# Использование:
#   deploy/install-ca.sh            # установить CA в системное хранилище
#   deploy/install-ca.sh --print    # только показать путь и подсказку по env
#
# ВАЖНО (README, раздел 0): устанавливать только на КОРПОРАТИВНЫХ устройствах
# уведомлённых сотрудников. Это меняет доверие TLS — применяется в рамках
# корпоративной политики, не тайно.

set -euo pipefail

CA_DIR="${DSP_CA_DIR:-$HOME/.mitmproxy}"
CA_PEM="$CA_DIR/mitmproxy-ca-cert.pem"
CA_CER="$CA_DIR/mitmproxy-ca-cert.cer"

if [[ ! -f "$CA_PEM" ]]; then
  echo "CA не найден: $CA_PEM"
  echo "Сначала запустите прокси, чтобы он сгенерировал CA:"
  echo "    cd deploy && docker compose up -d proxy"
  echo "затем повторите."
  exit 1
fi

print_hint() {
  echo "CA-сертификат: $CA_PEM"
  echo
  echo "Для CLI-агентов (Node/Python/curl) — прокидывается лаунчером, но при ручном запуске:"
  echo "    export NODE_EXTRA_CA_CERTS=\"$CA_PEM\""
  echo "    export REQUESTS_CA_BUNDLE=\"$CA_PEM\""
  echo "    export SSL_CERT_FILE=\"$CA_PEM\""
}

if [[ "${1:-}" == "--print" ]]; then
  print_hint
  exit 0
fi

OS="$(uname -s)"
case "$OS" in
  Darwin)
    echo "macOS: установка CA в System keychain (потребуется пароль/sudo)..."
    sudo security add-trusted-cert -d -r trustRoot \
      -k /Library/Keychains/System.keychain "$CA_PEM"
    echo "Готово. CA добавлен в системное доверенное хранилище."
    ;;
  Linux)
    echo "Linux: установка CA в /usr/local/share/ca-certificates (потребуется sudo)..."
    sudo cp "$CA_PEM" /usr/local/share/ca-certificates/mitmproxy-dsp.crt
    sudo update-ca-certificates
    echo "Готово."
    ;;
  *)
    echo "ОС '$OS' не поддерживается этим скриптом. Установите CA вручную:"
    echo "  $CA_PEM"
    ;;
esac

echo
print_hint
echo
echo "Проверка: deploy/install-ca.sh --print  ·  затем запускайте агентов через launcher/dsp-launch"
