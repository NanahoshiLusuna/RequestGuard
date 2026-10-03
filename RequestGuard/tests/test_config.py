"""Environment parsing."""

import os
import unittest

from requestguard.config import Config

_KEYS = (
    "ABUSEIPDB_API_KEY",
    "LISTEN_HOST",
    "LISTEN_PORT",
    "LISTEN_PORTS",
    "UPSTREAM_HOST",
    "UPSTREAM_PORT",
    "BAN_DAYS",
    "MAX_BAN_DAYS",
    "RATE_LIMIT_PER_SEC",
    "ABUSE_SCORE_THRESHOLD",
    "WHITELIST",
    "TRUST_COUNTRIES",
    "MIXED_COUNTRIES",
    "TRUST_SCORE_THRESHOLD",
    "TRUST_RATE_LIMIT_PER_SEC",
    "LOW_SCORE_THRESHOLD",
    "LOW_RATE_LIMIT_PER_SEC",
)


class ConfigTest(unittest.TestCase):
    def setUp(self) -> None:
        self._saved = {key: os.environ.get(key) for key in _KEYS}
        for key in _KEYS:
            os.environ.pop(key, None)

    def tearDown(self) -> None:
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def test_missing_key(self) -> None:
        with self.assertRaises(SystemExit):
            Config.from_env()

    def test_confirm_link_is_rejected(self) -> None:
        os.environ["ABUSEIPDB_API_KEY"] = "https://www.abuseipdb.com/register/confirm/example"
        with self.assertRaises(SystemExit):
            Config.from_env()

    def test_defaults(self) -> None:
        os.environ["ABUSEIPDB_API_KEY"] = "test-key"
        cfg = Config.from_env()
        self.assertEqual(cfg.ban_days, 30)
        self.assertEqual(cfg.rate_limit_per_sec, 30)
        self.assertEqual(cfg.abuse_score_threshold, 75)
        self.assertEqual(cfg.max_ban_days, 365)
        self.assertEqual(cfg.trust_countries, frozenset({"KR", "JP"}))
        self.assertEqual(cfg.mixed_countries, frozenset({"US"}))
        self.assertEqual(cfg.trust_score_threshold, 90)
        self.assertEqual(cfg.trust_rate_limit_per_sec, 60)
        self.assertEqual(cfg.low_score_threshold, 25)
        self.assertEqual(cfg.low_rate_limit_per_sec, 10)
        self.assertFalse(cfg.listen_all)
        self.assertFalse(cfg.same_port)

    def test_same_port_loop_is_rejected(self) -> None:
        os.environ["ABUSEIPDB_API_KEY"] = "test-key"
        os.environ["LISTEN_PORT"] = "8080"
        os.environ["UPSTREAM_PORT"] = "8080"
        os.environ["UPSTREAM_HOST"] = "127.0.0.1"
        with self.assertRaises(SystemExit):
            Config.from_env()

    def test_same_port_on_another_machine_is_allowed(self) -> None:
        os.environ["ABUSEIPDB_API_KEY"] = "test-key"
        os.environ["LISTEN_HOST"] = "0.0.0.0"
        os.environ["LISTEN_PORT"] = "8080"
        os.environ["UPSTREAM_HOST"] = "10.0.0.5"
        os.environ["UPSTREAM_PORT"] = "8080"
        cfg = Config.from_env()
        self.assertEqual(cfg.upstream_host, "10.0.0.5")
        self.assertEqual(cfg.upstream_port, 8080)

    def test_all_ports_forward_to_the_same_port(self) -> None:
        os.environ["ABUSEIPDB_API_KEY"] = "test-key"
        os.environ["LISTEN_PORTS"] = "all"
        cfg = Config.from_env()
        self.assertTrue(cfg.listen_all)
        self.assertTrue(cfg.same_port)
        self.assertEqual(cfg.upstream_host, "127.0.0.1")

    def test_port_list_and_range(self) -> None:
        os.environ["ABUSEIPDB_API_KEY"] = "test-key"
        os.environ["LISTEN_PORTS"] = "80,443,8000-8002"
        cfg = Config.from_env()
        self.assertEqual(cfg.listen_ports, (80, 443, 8000, 8001, 8002))
        self.assertTrue(cfg.same_port)
        self.assertFalse(cfg.listen_all)

    def test_same_port_on_loopback_is_rejected(self) -> None:
        os.environ["ABUSEIPDB_API_KEY"] = "test-key"
        os.environ["LISTEN_HOST"] = "127.0.0.1"
        os.environ["LISTEN_PORTS"] = "3000"
        with self.assertRaises(SystemExit):
            Config.from_env()

    def test_country_lists_reject_overlap(self) -> None:
        os.environ["ABUSEIPDB_API_KEY"] = "test-key"
        os.environ["TRUST_COUNTRIES"] = "KR,US"
        os.environ["MIXED_COUNTRIES"] = "US"
        with self.assertRaises(SystemExit):
            Config.from_env()

    def test_whitelist_accepts_ip_and_mac(self) -> None:
        os.environ["ABUSEIPDB_API_KEY"] = "test-key"
        os.environ["WHITELIST"] = "10.0.0.8, AA-BB-CC-DD-EE-FF"
        cfg = Config.from_env()
        self.assertEqual(cfg.whitelist, frozenset({"10.0.0.8", "mac:aa:bb:cc:dd:ee:ff"}))


if __name__ == "__main__":
    unittest.main()
