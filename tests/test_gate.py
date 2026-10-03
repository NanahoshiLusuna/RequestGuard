"""Blacklist, rate, and ban-expiry decisions."""

import threading
import unittest

from requestguard.abuseipdb import CheckResult
from requestguard.config import Config
from requestguard.gate import Gate, rate_ban_days
from requestguard.http_parse import RequestError, parse_request_bytes
from requestguard.net import is_public, normalize_ip
from requestguard.store import Store

IP = "8.8.8.8"
DAY = 86400


class Clock:
    def __init__(self) -> None:
        self.t = 1_700_000_000.0

    def __call__(self) -> float:
        return self.t


class FakeAbuse:
    def __init__(self, score: int = 0, error: str = "", country: str = "") -> None:
        self.score = score
        self.error = error
        self.country = country
        self.calls: list[str] = []
        self._lock = threading.Lock()

    def check(self, ip: str) -> CheckResult:
        with self._lock:
            self.calls.append(ip)
        if self.error:
            return CheckResult(ok=False, error=self.error)
        return CheckResult(ok=True, score=self.score, country=self.country)


def config(**kwargs) -> Config:
    values = dict(api_key="test-key", listen_host="127.0.0.1", listen_port=0, upstream_port=9)
    values.update(kwargs)
    return Config(**values)


def good_request(cfg: Config):
    return parse_request_bytes(b"GET / HTTP/1.1\r\nHost: t\r\n\r\n", cfg)


class RateFormulaTest(unittest.TestCase):
    def test_threshold_and_scale(self) -> None:
        self.assertEqual(rate_ban_days(29, threshold=30, base_days=30, max_days=365), 0)
        self.assertEqual(rate_ban_days(30, threshold=30, base_days=30, max_days=365), 30)
        self.assertEqual(rate_ban_days(31, threshold=30, base_days=30, max_days=365), 31)
        self.assertEqual(rate_ban_days(60, threshold=30, base_days=30, max_days=365), 60)
        self.assertEqual(rate_ban_days(120, threshold=30, base_days=30, max_days=365), 120)
        self.assertEqual(rate_ban_days(10000, threshold=30, base_days=30, max_days=365), 365)


class GateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = Clock()
        self.cfg = config()
        self.abuse = FakeAbuse()
        self.store = Store(":memory:")
        self.gate = Gate(self.cfg, self.store, self.abuse, now=self.clock, links=lambda _ip: None)
        self.good = good_request(self.cfg)

    def tearDown(self) -> None:
        self.store.close()

    def test_first_public_request_checks_once(self) -> None:
        first = self.gate.evaluate(IP, self.good)
        second = self.gate.evaluate(IP, self.good)
        self.assertEqual(first.action, "allow")
        self.assertEqual(second.action, "allow")
        self.assertEqual(self.abuse.calls, [IP])

    def test_private_ip_skips_api(self) -> None:
        decision = self.gate.evaluate("127.0.0.1", self.good)
        self.assertEqual(decision.action, "allow")
        self.assertEqual(self.abuse.calls, [])
        again = self.gate.evaluate("::ffff:10.1.2.3", self.good)
        self.assertEqual(again.action, "allow")
        self.assertEqual(self.abuse.calls, [])

    def test_score_threshold(self) -> None:
        self.abuse.score = 74
        allowed = self.gate.evaluate(IP, self.good)
        self.assertEqual(allowed.action, "allow")

        self.clock.t += 31 * DAY
        self.abuse.score = 75
        blocked = self.gate.evaluate(IP, self.good)
        self.assertEqual(blocked.action, "block")
        self.assertEqual(blocked.reason, "blacklist")
        self.assertEqual(blocked.expires_at, int(self.clock.t) + 30 * DAY)

    def test_blacklist_wins_over_format_on_the_same_request(self) -> None:
        self.abuse.score = 90
        decision = self.gate.evaluate(IP, RequestError("nul", True, 400))
        self.assertEqual(decision.reason, "blacklist")
        self.assertEqual(self.abuse.calls, [IP])

    def test_hostile_format_bans_for_a_month(self) -> None:
        decision = self.gate.evaluate(IP, RequestError("nul", True, 400))
        self.assertEqual(decision.action, "block")
        self.assertEqual(decision.reason, "format")
        self.assertEqual(decision.expires_at, int(self.clock.t) + 30 * DAY)
        self.assertEqual(self.abuse.calls, [IP])
        later = self.gate.evaluate(IP, self.good)
        self.assertEqual(later.action, "block")
        self.assertEqual(self.abuse.calls, [IP])

    def test_ordinary_mistake_is_not_stored(self) -> None:
        decision = self.gate.evaluate(IP, RequestError("missing_host", False, 400))
        self.assertEqual(decision.action, "reject")
        self.assertIsNone(self.store.get_ban(IP, self.clock.t))

    def test_api_failure_uses_local_policy(self) -> None:
        self.abuse.error = "http_429"
        decision = self.gate.evaluate(IP, self.good)
        self.assertEqual(decision.action, "allow")
        self.assertIsNone(self.store.get_ban(IP, self.clock.t))
        blocked = self.gate.evaluate(IP, RequestError("nul", True, 400))
        self.assertEqual(blocked.action, "block")
        self.assertEqual(blocked.reason, "format")
        self.abuse.error = ""
        self.abuse.score = 0
        later = self.gate.evaluate(IP, self.good)
        self.assertEqual(later.reason, "format")
        self.assertEqual(self.abuse.calls, [IP, IP])

    def test_api_failure_still_rate_limits(self) -> None:
        self.abuse.error = "http_401"
        decisions = [self.gate.evaluate(IP, self.good) for _ in range(30)]
        self.assertEqual(decisions[28].action, "allow")
        self.assertEqual(decisions[29].action, "block")
        self.assertEqual(decisions[29].reason, "rate")

    def test_api_failure_checks_again_when_it_recovers(self) -> None:
        self.abuse.error = "http_429"
        self.assertEqual(self.gate.evaluate(IP, self.good).action, "allow")
        self.abuse.error = ""
        self.abuse.score = 90
        blocked = self.gate.evaluate(IP, self.good)
        self.assertEqual(blocked.reason, "blacklist")
        self.assertEqual(self.abuse.calls, [IP, IP])

    def test_thirty_per_second_bans_and_faster_lasts_longer(self) -> None:
        decisions = [self.gate.evaluate(IP, self.good) for _ in range(60)]
        self.assertEqual(decisions[28].action, "allow")
        self.assertEqual(decisions[29].action, "block")
        self.assertEqual(decisions[29].reason, "rate")
        self.assertEqual(decisions[29].expires_at, int(self.clock.t) + 30 * DAY)
        self.assertEqual(decisions[-1].expires_at, int(self.clock.t) + 60 * DAY)
        self.assertEqual(self.abuse.calls, [IP])

    def test_window_expires_after_one_second(self) -> None:
        for _ in range(29):
            self.assertEqual(self.gate.evaluate(IP, self.good).action, "allow")
        self.clock.t += 1.1
        for _ in range(29):
            self.assertEqual(self.gate.evaluate(IP, self.good).action, "allow")
        self.assertIsNone(self.store.get_ban(IP, self.clock.t))

    def test_later_weaker_event_does_not_shorten_a_long_ban(self) -> None:
        for _ in range(60):
            self.gate.evaluate(IP, self.good)
        self.clock.t += 2
        before = self.store.get_ban(IP, self.clock.t)
        assert before is not None
        decision = self.gate.evaluate(IP, RequestError("nul", True, 400))
        after = self.store.get_ban(IP, self.clock.t)
        assert after is not None
        self.assertEqual(decision.action, "block")
        self.assertEqual(after.expires_at, before.expires_at)
        self.assertEqual(after.reason, "rate")

    def test_extreme_burst_caps_at_max_days(self) -> None:
        last = None
        for _ in range(400):
            last = self.gate.evaluate(IP, self.good)
        assert last is not None
        self.assertEqual(last.expires_at, int(self.clock.t) + 365 * DAY)

    def test_expired_ban_checks_the_ip_again(self) -> None:
        self.abuse.score = 90
        banned = self.gate.evaluate(IP, self.good)
        self.assertEqual(banned.reason, "blacklist")
        self.clock.t = float(banned.expires_at or 0)
        self.abuse.score = 0
        allowed = self.gate.evaluate(IP, self.good)
        self.assertEqual(allowed.action, "allow")
        self.assertEqual(self.abuse.calls, [IP, IP])

    def test_whitelist_skips_blacklist_and_rate(self) -> None:
        cfg = config(whitelist=frozenset({IP}))
        abuse = FakeAbuse(score=100)
        store = Store(":memory:")
        gate = Gate(cfg, store, abuse, now=self.clock)
        try:
            for _ in range(40):
                decision = gate.evaluate(IP, self.good)
                self.assertEqual(decision.action, "allow")
            rejected = gate.evaluate(IP, RequestError("nul", True, 400))
            self.assertEqual(rejected.action, "reject")
            self.assertIsNone(store.get_ban(IP, self.clock.t))
            self.assertEqual(abuse.calls, [])
        finally:
            store.close()

    def test_body_format_ban_does_not_check_again(self) -> None:
        self.assertEqual(self.gate.evaluate(IP, self.good).action, "allow")
        decision = self.gate.note_format(IP, RequestError("bad_chunk", True, 400))
        self.assertEqual(decision.reason, "format")
        self.assertEqual(decision.expires_at, int(self.clock.t) + 30 * DAY)
        plain = self.gate.note_format(IP, RequestError("truncated_body", False, 400))
        self.assertEqual(plain.action, "block")
        self.assertEqual(self.abuse.calls, [IP])

    def test_concurrent_first_sight_uses_one_lookup(self) -> None:
        errors: list[BaseException] = []

        def _run() -> None:
            try:
                self.gate.evaluate(IP, self.good)
            except BaseException as exc:  # noqa: BLE001 - collect worker failures
                errors.append(exc)

        threads = [threading.Thread(target=_run) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(2)
        self.assertEqual(errors, [])
        self.assertEqual(self.abuse.calls, [IP])

    def test_normalize(self) -> None:
        self.assertEqual(normalize_ip("::ffff:8.8.8.8"), "8.8.8.8")
        self.assertFalse(is_public("10.1.2.3"))
        self.assertTrue(is_public("8.8.8.8"))

    def test_mac_rate_follows_a_device_across_ips(self) -> None:
        mac = "aa:bb:cc:dd:ee:ff"
        other = "1.1.1.1"
        gate = Gate(self.cfg, self.store, self.abuse, now=self.clock, links=lambda _ip: mac)
        for _ in range(20):
            self.assertEqual(gate.evaluate(IP, self.good).action, "allow")
        allowed = 0
        blocked = None
        for _ in range(10):
            decision = gate.evaluate(other, self.good)
            if decision.action == "allow":
                allowed += 1
            else:
                blocked = decision
        self.assertEqual(allowed, 9)
        assert blocked is not None
        self.assertEqual(blocked.reason, "rate")
        self.assertIsNotNone(self.store.get_ban(f"mac:{mac}", self.clock.t))
        self.assertIsNotNone(self.store.get_ban(other, self.clock.t))
        again = gate.evaluate(IP, self.good)
        self.assertEqual(again.action, "block")
        self.assertIsNotNone(self.store.get_ban(IP, self.clock.t))

    def test_format_ban_follows_the_mac(self) -> None:
        mac = "aa:bb:cc:dd:ee:ff"
        other = "1.1.1.1"
        gate = Gate(self.cfg, self.store, self.abuse, now=self.clock, links=lambda _ip: mac)
        blocked = gate.evaluate(IP, RequestError("nul", True, 400))
        self.assertEqual(blocked.reason, "format")
        moved = gate.evaluate(other, self.good)
        self.assertEqual(moved.reason, "format")
        saved = self.store.get_ban(other, self.clock.t)
        assert saved is not None
        self.assertEqual(saved.expires_at, blocked.expires_at)
        self.assertEqual(self.abuse.calls, [IP])

    def test_blacklist_covers_the_observed_mac(self) -> None:
        mac = "aa:bb:cc:dd:ee:ff"
        self.abuse.score = 90
        gate = Gate(self.cfg, self.store, self.abuse, now=self.clock, links=lambda _ip: mac)
        decision = gate.evaluate(IP, self.good)
        self.assertEqual(decision.reason, "blacklist")
        saved = self.store.get_ban(f"mac:{mac}", self.clock.t)
        assert saved is not None
        self.assertEqual(saved.reason, "blacklist")
        self.assertEqual(self.abuse.calls, [IP])

    def test_other_mac_is_a_different_client(self) -> None:
        macs = {"8.8.8.8": "aa:bb:cc:dd:ee:01", "1.1.1.1": "aa:bb:cc:dd:ee:02"}
        gate = Gate(self.cfg, self.store, self.abuse, now=self.clock, links=lambda ip: macs.get(ip))
        decisions = [gate.evaluate(IP, self.good) for _ in range(30)]
        self.assertEqual(decisions[29].reason, "rate")
        other = gate.evaluate("1.1.1.1", self.good)
        self.assertEqual(other.action, "allow")

    def test_whitelist_mac_skips_the_gate(self) -> None:
        mac = "aa:bb:cc:dd:ee:ff"
        cfg = config(whitelist=frozenset({f"mac:{mac}"}))
        abuse = FakeAbuse(score=100)
        store = Store(":memory:")
        gate = Gate(cfg, store, abuse, now=self.clock, links=lambda _ip: mac)
        try:
            for _ in range(40):
                self.assertEqual(gate.evaluate(IP, self.good).action, "allow")
            self.assertIsNone(store.get_ban(IP, self.clock.t))
            self.assertEqual(abuse.calls, [])
        finally:
            store.close()

    def test_mac_lookup_error_uses_the_ip(self) -> None:
        def _boom(_ip: str) -> str:
            raise RuntimeError("no table")

        gate = Gate(self.cfg, self.store, self.abuse, now=self.clock, links=_boom)
        self.assertEqual(gate.evaluate(IP, self.good).action, "allow")
        self.assertIsNone(self.store.get_ban(IP, self.clock.t))

    def test_country_rank_changes_the_score_bar(self) -> None:
        self.abuse.country = "KR"
        self.abuse.score = 89
        trusted = self.gate.evaluate("1.0.0.1", self.good)
        self.assertEqual(trusted.action, "allow")
        self.abuse.score = 90
        blocked = self.gate.evaluate("1.0.0.2", self.good)
        self.assertEqual(blocked.reason, "blacklist")
        self.assertIn("country=KR", blocked.detail)
        self.assertIn("rank=trust", blocked.detail)

        self.abuse.country = "JP"
        self.abuse.score = 89
        self.assertEqual(self.gate.evaluate("1.0.0.3", self.good).action, "allow")

        self.abuse.country = "US"
        self.abuse.score = 74
        self.assertEqual(self.gate.evaluate("1.0.0.4", self.good).action, "allow")
        self.abuse.score = 75
        mixed = self.gate.evaluate("1.0.0.5", self.good)
        self.assertEqual(mixed.reason, "blacklist")
        self.assertIn("rank=mixed", mixed.detail)

        self.abuse.country = "CN"
        self.abuse.score = 24
        self.assertEqual(self.gate.evaluate("1.0.0.6", self.good).action, "allow")
        self.abuse.score = 25
        low = self.gate.evaluate("1.0.0.7", self.good)
        self.assertEqual(low.reason, "blacklist")
        self.assertIn("country=CN", low.detail)
        self.assertIn("rank=low", low.detail)

        self.abuse.country = "DE"
        self.abuse.score = 25
        other = self.gate.evaluate("1.0.0.8", self.good)
        self.assertEqual(other.reason, "blacklist")
        self.assertIn("rank=low", other.detail)

    def test_low_country_rate_is_stricter_after_lookup(self) -> None:
        self.abuse.country = "CN"
        self.abuse.score = 0
        decisions = [self.gate.evaluate(IP, self.good) for _ in range(10)]
        self.assertEqual(decisions[8].action, "allow")
        self.assertEqual(decisions[9].reason, "rate")
        self.assertIn("rank=low", decisions[9].detail)

    def test_trusted_country_keeps_a_higher_rate(self) -> None:
        self.abuse.country = "KR"
        self.abuse.score = 0
        decisions = [self.gate.evaluate(IP, self.good) for _ in range(40)]
        self.assertTrue(all(item.action == "allow" for item in decisions))

    def test_private_ip_keeps_the_default_rate(self) -> None:
        decisions = [self.gate.evaluate("10.1.2.3", self.good) for _ in range(15)]
        self.assertTrue(all(item.action == "allow" for item in decisions))


if __name__ == "__main__":
    unittest.main()
