"""mitmproxy addon — сердце Data Plane.

Хуки:
  http_connect : читает identity из Proxy-Authorization при CONNECT (TLS-туннель);
  request      : классифицирует провайдера, извлекает промпт, сканирует DLP,
                 копит частичное событие на flow;
  response     : дополняет токенами/ответом, пишет ОДНО событие на обмен;
  error        : если ответа не было — всё равно фиксирует egress-событие.

Режим MVP — alert-only: события пишутся, трафик не блокируется.

Запуск:  mitmdump -s proxy/addon.py   (см. deploy/, README).
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Dict, Optional

# --- делаем пакеты репозитория импортируемыми внутри процесса mitmproxy ------
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from catalog import classify, parse_request, parse_response  # noqa: E402
from dlp import DlpEngine  # noqa: E402
from proxy.config import ProxyConfig  # noqa: E402
from proxy.identity import Identity, decode_proxy_authorization  # noqa: E402
from storage import Event, EventStore  # noqa: E402

log = logging.getLogger("dsp.proxy")


class DataShieldAddon:
    def __init__(self, config: Optional[ProxyConfig] = None) -> None:
        self.cfg = config or ProxyConfig.from_env()
        self.store = EventStore(self.cfg.db_path)
        self.dlp = DlpEngine(enforce=self.cfg.enforce)
        # identity по client_conn.id (устанавливается на CONNECT, живёт весь туннель)
        self._identity: Dict[str, Identity] = {}
        log.info(
            "DataShield addon загружен: db=%s alert_only=%s scan_responses=%s",
            self.cfg.db_path,
            not self.cfg.enforce,
            self.cfg.scan_responses,
        )

    # ------------------------------------------------------------------ #
    # Идентичность
    # ------------------------------------------------------------------ #

    def http_connect(self, flow) -> None:
        ident = decode_proxy_authorization(
            flow.request.headers.get("Proxy-Authorization")
        )
        if ident:
            self._identity[flow.client_conn.id] = ident

    def _resolve_identity(self, flow) -> Identity:
        # 1) из CONNECT-туннеля
        ident = self._identity.get(flow.client_conn.id)
        if ident:
            return ident
        # 2) из Proxy-Authorization прямо на запросе (plain HTTP через прокси)
        ident = decode_proxy_authorization(
            flow.request.headers.get("Proxy-Authorization")
        )
        if ident:
            return ident
        # 3) из явных заголовков (gateway-режим / reverse-proxy)
        h = flow.request.headers
        user = h.get("X-DSP-User")
        if user:
            return Identity(
                user=user, agent=h.get("X-DSP-Agent"), device=h.get("X-DSP-Device")
            )
        # 4) дефолт
        return Identity(user=self.cfg.default_user)

    # ------------------------------------------------------------------ #
    # Запрос
    # ------------------------------------------------------------------ #

    def request(self, flow) -> None:
        try:
            self._handle_request(flow)
        except Exception:  # addon не должен ломать проксирование
            log.exception("Ошибка обработки запроса")

    def _handle_request(self, flow) -> None:
        host = flow.request.pretty_host
        provider = classify(host)
        ident = self._resolve_identity(flow)

        parser = provider.parser if provider else "generic"
        content_type = flow.request.headers.get("content-type", "")
        body = self._get_content(flow.request)

        parsed = parse_request(parser, content_type, body)
        result = self.dlp.scan(parsed.text)

        device = ident.device or (
            flow.client_conn.peername[0] if flow.client_conn.peername else None
        )
        agent = ident.agent or (provider.known_agents[0] if provider and provider.known_agents else None)

        event = Event(
            user=ident.user,
            device=device,
            agent=agent,
            provider=provider.id if provider else None,
            model=parsed.model,
            destination=host,
            direction="request",
            tokens_in=parsed.tokens_in,
            bytes=len(body) if body else 0,
            verdict=result.verdict,
            matched_signatures=[f.to_dict() for f in result.findings],
        )
        # копим на flow; финализируем в response/error, чтобы не задваивать события
        flow.metadata["dsp_event"] = event
        flow.metadata["dsp_written"] = False

        if result.findings:
            log.warning(
                "DLP alert: user=%s agent=%s provider=%s dest=%s signatures=%s",
                event.user, event.agent, event.provider, host, result.signatures(),
            )

    # ------------------------------------------------------------------ #
    # Ответ
    # ------------------------------------------------------------------ #

    def response(self, flow) -> None:
        try:
            self._handle_response(flow)
        except Exception:
            log.exception("Ошибка обработки ответа")
            self._flush(flow)

    def _handle_response(self, flow) -> None:
        event: Optional[Event] = flow.metadata.get("dsp_event")
        if event is None:
            return

        if self.cfg.scan_responses and flow.response is not None:
            provider = classify(flow.request.pretty_host)
            parser = provider.parser if provider else "generic"
            content_type = flow.response.headers.get("content-type", "")
            body = self._get_content(flow.response)
            parsed = parse_response(parser, content_type, body)

            if parsed.tokens_in is not None:
                event.tokens_in = parsed.tokens_in
            event.tokens_out = parsed.tokens_out
            if not event.model and parsed.model:
                event.model = parsed.model

            resp_result = self.dlp.scan(parsed.text)
            if resp_result.findings:
                # ответ тоже может содержать чувствительное (эхо/утечка) — доклеиваем
                existing = {(f["detector"], f["fp"]) for f in event.matched_signatures}
                for f in resp_result.findings:
                    if (f.detector, f.fp) not in existing:
                        event.matched_signatures.append(f.to_dict())
                if event.matched_signatures:
                    event.verdict = "alert"

        self._flush(flow)

    def error(self, flow) -> None:
        # запрос ушёл, ответа нет — egress уже случился, фиксируем
        self._flush(flow)

    # ------------------------------------------------------------------ #
    # Вспомогательное
    # ------------------------------------------------------------------ #

    def _flush(self, flow) -> None:
        if flow.metadata.get("dsp_written"):
            return
        event: Optional[Event] = flow.metadata.get("dsp_event")
        if event is None:
            return
        try:
            self.store.record(event)
            flow.metadata["dsp_written"] = True
        except Exception:
            log.exception("Не удалось записать событие")

    def _get_content(self, message) -> bytes:
        """Декодированное (content-encoding) тело, обрезанное до лимита."""
        try:
            content = message.get_content(strict=False)
        except Exception:
            content = message.raw_content
        if not content:
            return b""
        if len(content) > self.cfg.max_body_bytes:
            content = content[: self.cfg.max_body_bytes]
        return content

    def done(self) -> None:
        try:
            self.store.close()
        except Exception:
            pass


# mitmproxy обнаруживает addons в списке `addons` на уровне модуля.
addons = [DataShieldAddon()]
