import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from catalog import classify, parse_request, parse_response  # noqa: E402


class TestClassifier(unittest.TestCase):
    def test_anthropic(self):
        p = classify("api.anthropic.com")
        self.assertIsNotNone(p)
        self.assertEqual(p.id, "anthropic")
        self.assertEqual(p.parser, "anthropic_messages")

    def test_subdomain(self):
        self.assertEqual(classify("foo.api.openai.com").id, "openai")

    def test_hostport(self):
        self.assertEqual(classify("api.anthropic.com:443").id, "anthropic")

    def test_unknown(self):
        self.assertIsNone(classify("example.com"))


class TestAnthropicParser(unittest.TestCase):
    def test_request_extracts_prompt(self):
        body = json.dumps({
            "model": "claude-sonnet-5",
            "system": "You are helpful.",
            "messages": [
                {"role": "user", "content": "my secret is AKIAIOSFODNN7EXAMPLE"},
                {"role": "assistant", "content": [{"type": "text", "text": "ok"}]},
            ],
        }).encode()
        parsed = parse_request("anthropic_messages", "application/json", body)
        self.assertEqual(parsed.model, "claude-sonnet-5")
        self.assertIn("AKIAIOSFODNN7EXAMPLE", parsed.text)
        self.assertIn("You are helpful.", parsed.text)

    def test_response_tokens(self):
        body = json.dumps({
            "model": "claude-sonnet-5",
            "content": [{"type": "text", "text": "hello world"}],
            "usage": {"input_tokens": 12, "output_tokens": 5},
        }).encode()
        parsed = parse_response("anthropic_messages", "application/json", body)
        self.assertEqual(parsed.tokens_in, 12)
        self.assertEqual(parsed.tokens_out, 5)
        self.assertIn("hello world", parsed.text)

    def test_response_sse(self):
        sse = (
            'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Hel"}}\n'
            'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"lo"}}\n'
            "data: [DONE]\n"
        ).encode()
        parsed = parse_response("anthropic_messages", "text/event-stream", sse)
        self.assertIn("Hel", parsed.text)
        self.assertIn("lo", parsed.text)


class TestOpenAIParser(unittest.TestCase):
    def test_request(self):
        body = json.dumps({
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "hi there"}],
        }).encode()
        parsed = parse_request("openai_chat", "application/json", body)
        self.assertEqual(parsed.model, "gpt-4")
        self.assertIn("hi there", parsed.text)

    def test_response(self):
        body = json.dumps({
            "model": "gpt-4",
            "choices": [{"message": {"role": "assistant", "content": "answer"}}],
            "usage": {"prompt_tokens": 3, "completion_tokens": 2},
        }).encode()
        parsed = parse_response("openai_chat", "application/json", body)
        self.assertEqual(parsed.tokens_in, 3)
        self.assertEqual(parsed.tokens_out, 2)
        self.assertIn("answer", parsed.text)


class TestGenericParser(unittest.TestCase):
    def test_json_walk(self):
        body = json.dumps({"foo": {"bar": "hidden secret text"}}).encode()
        parsed = parse_request("generic", "application/json", body)
        self.assertIn("hidden secret text", parsed.text)

    def test_plain_text(self):
        parsed = parse_request("generic", "text/plain", b"just raw text")
        self.assertIn("just raw text", parsed.text)

    def test_binary_response_skipped(self):
        parsed = parse_response("generic", "image/png", b"\x89PNG\r\n")
        self.assertEqual(parsed.text, "")

    def test_malformed_json_falls_back(self):
        parsed = parse_request("anthropic_messages", "application/json", b"{not json")
        self.assertEqual(parsed.parser, "generic")


if __name__ == "__main__":
    unittest.main()
