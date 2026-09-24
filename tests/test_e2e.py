"""Сквозной тест core-loop (DoD MVP) без транспорта mitmproxy.

Проверяем цепочку: классификация провайдера → парсинг тела → DLP-скан →
запись события с атрибуцией пользователю → отчёт показывает инцидент.
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from catalog import classify, parse_request  # noqa: E402
from dlp import DlpEngine  # noqa: E402
from storage import Event, EventStore  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "sample_prompts.json")


def _pipeline(store, dlp, user, host, body_dict):
    """Мини-повтор логики addon: request → parse → scan → record."""
    provider = classify(host)
    parser = provider.parser if provider else "generic"
    body = json.dumps(body_dict).encode()
    parsed = parse_request(parser, "application/json", body)
    result = dlp.scan(parsed.text)
    event = Event(
        user=user,
        agent="claude-code",
        provider=provider.id if provider else None,
        model=parsed.model,
        destination=host,
        direction="request",
        bytes=len(body),
        verdict=result.verdict,
        matched_signatures=[f.to_dict() for f in result.findings],
    )
    store.record(event)
    return result


class TestEndToEnd(unittest.TestCase):
    def setUp(self):
        self.store = EventStore(":memory:")
        self.dlp = DlpEngine()
        with open(FIXTURES, encoding="utf-8") as f:
            self.fx = json.load(f)

    def tearDown(self):
        self.store.close()

    def test_dod_planted_secret_flows_to_report(self):
        # alice отправляет промпт с посаженным AWS-ключом
        prompt = self.fx["aws_key"]
        result = _pipeline(
            self.store, self.dlp, "alice", "api.anthropic.com",
            {"model": "claude-sonnet-5", "messages": [{"role": "user", "content": prompt}]},
        )
        self.assertEqual(result.verdict, "alert")
        self.assertIn("aws_access_key", result.signatures())

        # чистый промпт от bob — без алерта
        _pipeline(
            self.store, self.dlp, "bob", "api.anthropic.com",
            {"model": "claude-sonnet-5", "messages": [{"role": "user", "content": self.fx["clean"]}]},
        )

        # отчёт: частота по пользователям
        usage = {r["user"]: r for r in self.store.usage_by_user()}
        self.assertEqual(usage["alice"]["requests"], 1)
        self.assertEqual(usage["alice"]["alerts"], 1)
        self.assertEqual(usage["bob"]["alerts"], 0)

        # инцидент атрибутирован alice и виден в отчёте
        incidents = self.store.incidents()
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertEqual(inc["user"], "alice")
        self.assertEqual(inc["provider"], "anthropic")
        sigs = json.loads(inc["matched_signatures"])
        self.assertTrue(any(s["detector"] == "aws_access_key" for s in sigs))
        # сырьё не сохранено — только маска
        self.assertNotIn("IOSFODNN7", inc["matched_signatures"])

    def test_all_fixtures_flag_expected(self):
        expect = {
            "aws_key": "aws_access_key",
            "private_key": "private_key",
            "jwt": "jwt",
            "connection_string": "connection_string",
            "credit_card": "credit_card",
            "ru_inn": "ru_inn",
            "ru_snils": "ru_snils",
            "email": "email",
        }
        for key, detector in expect.items():
            result = self.dlp.scan(self.fx[key])
            self.assertIn(detector, result.signatures(),
                          f"фикстура {key}: ожидался детектор {detector}")

    def test_clean_prompt_no_alert(self):
        result = self.dlp.scan(self.fx["clean"])
        self.assertEqual(result.verdict, "allow")
        self.assertEqual(result.findings, [])


if __name__ == "__main__":
    unittest.main()
