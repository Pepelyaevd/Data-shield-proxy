import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from catalog import is_telemetry  # noqa: E402


class TestTelemetryList(unittest.TestCase):
    def test_known_telemetry_hosts(self):
        for h in (
            "o123.ingest.sentry.io",
            "ingest.sentry.io",
            "statsig.com",
            "featuregates.org",
            "api.datadoghq.com",
            "browser-intake-datadoghq.com",       # «склеенный» интейк-домен
            "browser-intake-us5-datadoghq.com",
            "app.launchdarkly.com",
            "www.google-analytics.com",
        ):
            self.assertTrue(is_telemetry(h), f"должно быть телеметрией: {h}")

    def test_llm_providers_not_telemetry(self):
        for h in ("api.anthropic.com", "api.openai.com", "claude.ai", "example.com"):
            self.assertFalse(is_telemetry(h), f"не телеметрия: {h}")

    def test_hostport_and_trailing_dot(self):
        self.assertTrue(is_telemetry("statsig.com:443"))
        self.assertTrue(is_telemetry("statsig.com."))

    def test_none_and_empty(self):
        self.assertFalse(is_telemetry(None))
        self.assertFalse(is_telemetry(""))


if __name__ == "__main__":
    unittest.main()
