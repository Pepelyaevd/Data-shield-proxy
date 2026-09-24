import base64
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from proxy.identity import (  # noqa: E402
    encode_proxy_userinfo, decode_proxy_authorization,
)


class TestIdentity(unittest.TestCase):
    def test_roundtrip(self):
        userinfo = encode_proxy_userinfo("alice", "123456")
        header = "Basic " + base64.b64encode(userinfo.encode()).decode()
        ident = decode_proxy_authorization(header)
        self.assertIsNotNone(ident)
        self.assertEqual(ident.user, "alice")
        self.assertEqual(ident.secret, "123456")

    def test_user_only(self):
        userinfo = encode_proxy_userinfo("bob")
        header = "Basic " + base64.b64encode(userinfo.encode()).decode()
        ident = decode_proxy_authorization(header)
        self.assertEqual(ident.user, "bob")
        self.assertIsNone(ident.secret)

    def test_special_chars(self):
        userinfo = encode_proxy_userinfo("user@corp", "s3cr3t/pass")
        header = "Basic " + base64.b64encode(userinfo.encode()).decode()
        ident = decode_proxy_authorization(header)
        self.assertEqual(ident.user, "user@corp")
        self.assertEqual(ident.secret, "s3cr3t/pass")

    def test_invalid(self):
        self.assertIsNone(decode_proxy_authorization(None))
        self.assertIsNone(decode_proxy_authorization("Bearer xyz"))
        self.assertIsNone(decode_proxy_authorization("garbage"))


if __name__ == "__main__":
    unittest.main()
