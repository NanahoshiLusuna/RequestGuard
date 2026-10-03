"""Hostile HTTP is marked for a ban. Ordinary mistakes are not."""

import unittest

from requestguard.config import Config
from requestguard.http_parse import RequestError, parse_request_bytes


def parse(raw: bytes, **kwargs):
    cfg = Config(api_key="test-key", **kwargs)
    try:
        return parse_request_bytes(raw, cfg)
    except RequestError as exc:
        return exc


class ParseTest(unittest.TestCase):
    def test_ordinary_request(self) -> None:
        parsed = parse(b"GET /hi HTTP/1.1\r\nHost: t\r\n\r\n")
        self.assertEqual(parsed.method, "GET")
        self.assertEqual(parsed.target, "/hi")

    def test_chunked_body(self) -> None:
        raw = b"POST / HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
        parsed = parse(raw)
        self.assertEqual(parsed.body, b"hello")

    def test_hostile_shapes_are_banned(self) -> None:
        samples = [
            b"\x00\r\n\r\n",
            b"GET /a/../b HTTP/1.1\r\nHost: t\r\n\r\n",
            b"GET /%2e%2e/secret HTTP/1.1\r\nHost: t\r\n\r\n",
            b"GET http://evil.example/ HTTP/1.1\r\nHost: t\r\n\r\n",
            b"CONNECT evil.example:443 HTTP/1.1\r\nHost: t\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\nzzzz\r\n",
            b"GET / HTTP/1.1\r\nHost: t\r\nX-Bad: a\rb\r\n\r\n",
        ]
        for raw in samples:
            with self.subTest(raw=raw[:40]):
                result = parse(raw)
                self.assertIsInstance(result, RequestError)
                self.assertTrue(result.ban)

    def test_ordinary_mistakes_are_not_banned(self) -> None:
        samples = [
            b"GET / HTTP/1.1\nHost: t\n\n",
            b"GET / HTTP/1.1\r\n\r\n",
            b"GET / HTTP/2.0\r\nHost: t\r\n\r\n",
        ]
        for raw in samples:
            with self.subTest(raw=raw):
                result = parse(raw)
                self.assertIsInstance(result, RequestError)
                self.assertFalse(result.ban)

    def test_huge_header_is_banned(self) -> None:
        raw = b"GET / HTTP/1.1\r\nHost: t\r\nX: " + (b"a" * 200) + b"\r\n\r\n"
        result = parse(raw, max_header_bytes=128)
        self.assertIsInstance(result, RequestError)
        self.assertTrue(result.ban)
        self.assertEqual(result.code, "headers_too_large")


if __name__ == "__main__":
    unittest.main()
