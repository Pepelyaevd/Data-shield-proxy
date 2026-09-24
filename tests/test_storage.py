import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from storage import Event, EventStore  # noqa: E402


class TestEventStore(unittest.TestCase):
    def setUp(self):
        self.store = EventStore(":memory:")

    def tearDown(self):
        self.store.close()

    def test_record_and_counts(self):
        self.store.record(Event(user="alice", agent="claude-code", provider="anthropic",
                                verdict="allow"))
        self.store.record(Event(user="alice", agent="claude-code", provider="anthropic",
                                verdict="alert",
                                matched_signatures=[{"detector": "aws_access_key",
                                                     "severity": "critical"}]))
        c = self.store.counts()
        self.assertEqual(c["total"], 2)
        self.assertEqual(c["alerts"], 1)

    def test_usage_by_user(self):
        for _ in range(3):
            self.store.record(Event(user="bob", agent="cli", provider="anthropic"))
        self.store.record(Event(user="carol", agent="cli", provider="openai"))
        rows = self.store.usage_by_user()
        by_user = {r["user"]: r for r in rows}
        self.assertEqual(by_user["bob"]["requests"], 3)
        self.assertEqual(by_user["carol"]["requests"], 1)

    def test_incidents_filter_by_user(self):
        self.store.record(Event(user="alice", verdict="alert",
                                matched_signatures=[{"detector": "email"}]))
        self.store.record(Event(user="bob", verdict="alert",
                                matched_signatures=[{"detector": "jwt"}]))
        alice = self.store.incidents(user="alice")
        self.assertEqual(len(alice), 1)
        self.assertEqual(alice[0]["user"], "alice")

    def test_top_problems_aggregates_and_ranks(self):
        self.store.record(Event(user="alice", verdict="alert", matched_signatures=[
            {"detector": "aws_access_key", "category": "secret",
             "severity": "critical", "count": 1},
            {"detector": "email", "category": "pii", "severity": "low", "count": 2},
        ]))
        self.store.record(Event(user="bob", verdict="alert", matched_signatures=[
            {"detector": "aws_access_key", "category": "secret",
             "severity": "critical", "count": 1},
        ]))
        # allow-событие не должно попадать в топ-проблемы
        self.store.record(Event(user="bob", verdict="allow"))
        problems = self.store.top_problems()
        self.assertEqual(problems[0]["detector"], "aws_access_key")  # critical → первый
        self.assertEqual(problems[0]["events"], 2)
        self.assertEqual(problems[0]["users"], 2)  # уникальные пользователи
        self.assertEqual(problems[0]["hits"], 2)   # сумма count

    def test_classify_level_rule(self):
        from storage.db import classify_level
        self.assertIsNone(classify_level(0, 0, 0, 0))       # чистый
        self.assertEqual(classify_level(0, 0, 0, 1), "yellow")
        self.assertEqual(classify_level(0, 0, 2, 0), "orange")
        self.assertEqual(classify_level(0, 1, 0, 0), "orange")
        self.assertEqual(classify_level(0, 3, 0, 0), "red")
        self.assertEqual(classify_level(1, 0, 0, 0), "red")
        self.assertEqual(classify_level(2, 0, 0, 0), "black")

    def test_user_risk_is_system_assigned(self):
        # alice: две критические находки → black; bob: одна low → yellow
        self.store.record(Event(user="alice", verdict="alert", matched_signatures=[
            {"detector": "aws_access_key", "severity": "critical", "count": 1}]))
        self.store.record(Event(user="alice", verdict="alert", matched_signatures=[
            {"detector": "aws_access_key", "severity": "critical", "count": 1}]))
        self.store.record(Event(user="bob", verdict="alert", matched_signatures=[
            {"detector": "email", "severity": "low", "count": 1}]))
        # carol — только allow, уровня быть не должно
        self.store.record(Event(user="carol", verdict="allow"))
        risk = self.store.user_risk()
        self.assertEqual(risk["alice"]["level"], "black")
        self.assertEqual(risk["alice"]["ncrit"], 2)
        self.assertIn("критич", risk["alice"]["reason"])
        self.assertEqual(risk["bob"]["level"], "yellow")
        self.assertNotIn("carol", risk)

    def test_period_bounds_filter(self):
        self.store.record(Event(user="old", ts="2020-01-01T00:00:00+00:00"))
        self.store.record(Event(user="new", ts="2026-09-01T00:00:00+00:00"))
        rows = self.store.usage_by_user(since="2025-01-01T00:00:00+00:00")
        users = {r["user"] for r in rows}
        self.assertIn("new", users)
        self.assertNotIn("old", users)


if __name__ == "__main__":
    unittest.main()
