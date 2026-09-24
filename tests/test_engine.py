import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dlp import DlpEngine  # noqa: E402


def sigs(result):
    return set(result.signatures())


class TestOverlapSuppression(unittest.TestCase):
    """Кросс-детекторная дедупликация по спанам (dedup в рамках одного скана)."""

    def setUp(self):
        self.eng = DlpEngine()

    def test_signature_suppresses_entropy_and_assignment(self):
        # openai_key ловится специфичной сигнатурой; тот же спан не должен
        # породить дублей high_entropy_string / credential_assignment.
        r = self.eng.scan("export OPENAI_API_KEY=sk-proj-abcdefghijklmnop1234567890ABCD")
        self.assertEqual(sigs(r), {"openai_key"})

    def test_signature_wins_over_assignment(self):
        r = self.eng.scan('aws_key = "AKIAIOSFODNN7EXAMPLE"')
        self.assertEqual(sigs(r), {"aws_access_key"})

    def test_independent_findings_all_kept(self):
        # Непересекающиеся находки не подавляют друг друга.
        r = self.eng.scan(
            "email a.b@corp.example and card 4111 1111 1111 1111"
        )
        self.assertIn("email", sigs(r))
        self.assertIn("credit_card", sigs(r))

    def test_same_value_deduped_with_count(self):
        r = self.eng.scan("AKIAIOSFODNN7EXAMPLE and again AKIAIOSFODNN7EXAMPLE")
        aws = [f for f in r.findings if f.detector == "aws_access_key"]
        self.assertEqual(len(aws), 1)
        self.assertEqual(aws[0].count, 2)


if __name__ == "__main__":
    unittest.main()
