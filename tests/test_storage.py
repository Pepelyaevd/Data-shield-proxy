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


if __name__ == "__main__":
    unittest.main()
