import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dlp.detectors import (  # noqa: E402
    detect_secrets, detect_pii, detect_entropy,
    luhn_valid, inn_valid, snils_valid, shannon_entropy,
)


def detectors_of(findings):
    return {f.detector for f in findings}


class TestValidators(unittest.TestCase):
    def test_luhn(self):
        self.assertTrue(luhn_valid("4111 1111 1111 1111"))
        self.assertFalse(luhn_valid("4111 1111 1111 1112"))

    def test_inn(self):
        self.assertTrue(inn_valid("7707083893"))   # валидный 10-значный
        self.assertFalse(inn_valid("1234567890"))

    def test_snils(self):
        self.assertTrue(snils_valid("112-233-445 95"))
        self.assertFalse(snils_valid("112-233-445 96"))

    def test_entropy(self):
        self.assertGreater(shannon_entropy("aB3$xY9!qW2#zK7&"), 3.0)
        self.assertLess(shannon_entropy("aaaaaaaa"), 1.0)


class TestSecretDetectors(unittest.TestCase):
    def test_aws_access_key(self):
        f = detect_secrets("key AKIAIOSFODNN7EXAMPLE end")
        self.assertIn("aws_access_key", detectors_of(f))

    def test_private_key(self):
        f = detect_secrets("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END")
        self.assertIn("private_key", detectors_of(f))

    def test_jwt(self):
        jwt = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
               "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
               "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
        self.assertIn("jwt", detectors_of(detect_secrets(jwt)))

    def test_connection_string(self):
        f = detect_secrets("postgres://admin:s3cr3tPass@db.internal:5432/prod")
        self.assertIn("connection_string", detectors_of(f))

    def test_credential_assignment(self):
        f = detect_secrets('password = "hunter2SuperSecret"')
        self.assertIn("credential_assignment", detectors_of(f))

    def test_snippet_is_masked(self):
        f = detect_secrets("AKIAIOSFODNN7EXAMPLE")
        aws = [x for x in f if x.detector == "aws_access_key"][0]
        self.assertNotIn("IOSFODNN7", aws.snippet)  # середина замаскирована
        self.assertTrue(aws.snippet.startswith("AKIA"))


class TestPiiDetectors(unittest.TestCase):
    def test_email(self):
        self.assertIn("email", detectors_of(detect_pii("write to a.b@corp.example")))

    def test_credit_card_luhn(self):
        self.assertIn("credit_card", detectors_of(detect_pii("card 4111 1111 1111 1111")))
        # невалидная по Луну не срабатывает как карта
        self.assertNotIn("credit_card", detectors_of(detect_pii("num 4111 1111 1111 1112")))

    def test_ru_inn(self):
        self.assertIn("ru_inn", detectors_of(detect_pii("ИНН 7707083893")))

    def test_ru_snils(self):
        self.assertIn("ru_snils", detectors_of(detect_pii("СНИЛС 112-233-445 95")))


class TestEntropyDetector(unittest.TestCase):
    def test_high_entropy(self):
        f = detect_entropy("token=Zx9Kq2Lm8Pw4Rt7Vn3Bc6Df1Gh5Jk0")
        self.assertIn("high_entropy_string", detectors_of(f))

    def test_plain_word_ignored(self):
        self.assertEqual(detect_entropy("informationtechnology"), [])

    def test_structural_noise_ignored(self):
        # git-SHA, md5/sha, UUID, длинные числа — не секреты, а служебные id.
        for noise in (
            "9f8a7c6b5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f00",   # git sha (hex40)
            "d41d8cd98f00b204e9800998ecf8427e",            # md5 (hex32)
            "550e8400-e29b-41d4-a716-446655440000",        # UUID
            "1716239022314159265321",                      # длинное число
        ):
            self.assertEqual(detect_entropy(noise), [], f"шум не должен ловиться: {noise}")

    def test_short_token_below_min_len(self):
        # 20 символов < нового min_len (24) — не срабатывает
        self.assertEqual(detect_entropy("Zx9Kq2Lm8Pw4Rt7Vn3B"), [])


if __name__ == "__main__":
    unittest.main()
