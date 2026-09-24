# Самодостаточный образ прокси Data-Shield-Proxy.
# Базируется на официальном образе mitmproxy (несёт свой Python 3.12 + mitmdump).
# Addon использует только stdlib + пакеты репозитория — доп. зависимости не нужны.
#
# Для разработки удобнее bind-mount кода (см. deploy/docker-compose.yml);
# этот Dockerfile нужен для «запечённого» образа под доставку.

FROM mitmproxy/mitmproxy:latest

WORKDIR /app

# Код прокси и его зависимости внутри репозитория.
COPY proxy/    /app/proxy/
COPY dlp/      /app/dlp/
COPY catalog/  /app/catalog/
COPY storage/  /app/storage/

ENV DSP_DB_PATH=/app/data/events.db
EXPOSE 8080

ENTRYPOINT ["mitmdump"]
CMD ["--listen-host", "0.0.0.0", "-p", "8080", \
     "-s", "/app/proxy/addon.py", \
     "--set", "stream_large_bodies=5m"]
