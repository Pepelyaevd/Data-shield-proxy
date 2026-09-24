"""Тесты гейта аутентификации прокси (общий секрет) в addon."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from proxy.addon import DataShieldAddon  # noqa: E402
from proxy.config import ProxyConfig  # noqa: E402
from proxy.identity import Identity  # noqa: E402


def _addon(secret="123456", user=""):
    cfg = ProxyConfig()
    cfg.db_path = ":memory:"
    cfg.proxy_secret = secret
    cfg.proxy_user = user
    return DataShieldAddon(config=cfg)


class TestProxyAuthGate(unittest.TestCase):
    def test_correct_secret_allows(self):
        a = _addon()
        self.assertTrue(a._check_secret(Identity(user="alice", secret="123456")))
        a.done()

    def test_wrong_secret_denied(self):
        a = _addon()
        self.assertFalse(a._check_secret(Identity(user="alice", secret="nope")))
        a.done()

    def test_missing_secret_denied(self):
        a = _addon()
        self.assertFalse(a._check_secret(Identity(user="alice", secret=None)))
        self.assertFalse(a._check_secret(None))
        a.done()

    def test_pinned_user(self):
        a = _addon(user="user")
        self.assertTrue(a._check_secret(Identity(user="user", secret="123456")))
        self.assertFalse(a._check_secret(Identity(user="alice", secret="123456")))
        a.done()

    def test_auth_disabled_allows_all(self):
        a = _addon(secret="")
        self.assertTrue(a._check_secret(None))
        self.assertTrue(a._check_secret(Identity(user="x", secret=None)))
        a.done()


if __name__ == "__main__":
    unittest.main()
