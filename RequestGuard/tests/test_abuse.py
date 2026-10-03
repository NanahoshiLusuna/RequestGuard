"""AbuseIPDB client."""

import io
import unittest
import urllib.error

from requestguard.abuseipdb import AbuseIPDB, _NoRedirect


class _Body:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def read(self) -> bytes:
        return self._data

    def close(self) -> None:
        return None


class AbuseTest(unittest.TestCase):
    def test_reads_score_for_the_normalized_ip(self) -> None:
        client = AbuseIPDB("secret", 30, 2)
        seen: dict[str, str] = {}

        def _open(request, timeout=None):
            seen["key"] = request.get_header("Key")
            seen["url"] = request.full_url
            seen["timeout"] = str(timeout)
            return _Body(b'{"data":{"abuseConfidenceScore":42,"countryCode":"us"}}')

        client._opener.open = _open
        result = client.check("::ffff:8.8.8.8")
        self.assertTrue(result.ok)
        self.assertEqual(result.score, 42)
        self.assertEqual(result.country, "US")
        self.assertEqual(seen["key"], "secret")
        self.assertIn("ipAddress=8.8.8.8", seen["url"])
        self.assertEqual(seen["timeout"], "2")

    def test_missing_country_is_other(self) -> None:
        client = AbuseIPDB("secret", 30, 2)

        def _open(request, timeout=None):
            return _Body(b'{"data":{"abuseConfidenceScore":0}}')

        client._opener.open = _open
        result = client.check("8.8.8.8")
        self.assertTrue(result.ok)
        self.assertEqual(result.country, "XX")

    def test_private_ip_is_not_sent(self) -> None:
        client = AbuseIPDB("secret", 30, 2)
        called = False

        def _open(request, timeout=None):
            nonlocal called
            called = True
            return _Body(b"{}")

        client._opener.open = _open
        result = client.check("127.0.0.1")
        self.assertFalse(result.ok)
        self.assertEqual(result.error, "private")
        self.assertFalse(called)

    def test_http_429_cools_down(self) -> None:
        client = AbuseIPDB("secret", 30, 2)
        calls = 0

        def _open(request, timeout=None):
            nonlocal calls
            calls += 1
            raise urllib.error.HTTPError(request.full_url, 429, "Too Many Requests", {}, io.BytesIO(b""))

        client._opener.open = _open
        first = client.check("8.8.8.8")
        second = client.check("1.1.1.1")
        self.assertEqual(first.error, "http_429")
        self.assertEqual(second.error, "cooldown")
        self.assertEqual(calls, 1)

    def test_redirect_is_not_followed(self) -> None:
        request = urllib.request.Request("https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8")
        with self.assertRaises(urllib.error.HTTPError) as caught:
            _NoRedirect().redirect_request(request, io.BytesIO(), 302, "Found", {}, "https://evil.example/")
        self.assertEqual(caught.exception.code, 302)
        self.assertEqual(caught.exception.url, request.full_url)
        caught.exception.close()


if __name__ == "__main__":
    unittest.main()
