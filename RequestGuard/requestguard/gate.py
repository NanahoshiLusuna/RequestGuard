"""Ban decisions: blacklist, request rate, and request shape."""

from __future__ import annotations

import logging
import math
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass

from requestguard.abuseipdb import AbuseIPDB, CheckResult
from requestguard.config import Config
from requestguard.country import rank_for, rate_limit, score_threshold
from requestguard.http_parse import ParsedRequest, RequestError
from requestguard.net import is_public, link_address, mac_key, normalize_ip, normalize_mac
from requestguard.store import Store

log = logging.getLogger("requestguard")


def rate_ban_days(rps: float, *, threshold: int, base_days: int, max_days: int) -> int:
    """Ban length for one second of traffic.

    Below `threshold` there is no ban. At the threshold the ban is `base_days`.
    Faster bursts scale linearly, so 60/s with a 30/s threshold and a 30-day
    base lasts 60 days. The result never exceeds `max_days`.
    """
    if rps < threshold:
        return 0
    # Integer ceil. Floating multiplication turns 30 * (31/30) into 32 days.
    count = math.ceil(rps)
    scaled = (base_days * count + threshold - 1) // threshold
    return min(max_days, max(base_days, scaled))


@dataclass(frozen=True)
class Decision:
    action: str
    status: int
    reason: str
    detail: str = ""
    expires_at: int | None = None


class RateLimiter:
    def __init__(self, threshold: int) -> None:
        self.threshold = threshold
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()
        self._observations = 0

    def observe(self, ip: str, now: float) -> int:
        with self._lock:
            hits = self._hits.setdefault(ip, deque())
            cutoff = now - 1.0
            while hits and hits[0] <= cutoff:
                hits.popleft()
            hits.append(now)
            self._observations += 1
            if self._observations % 1024 == 0 or len(self._hits) > 10000:
                self._sweep(now)
            return len(hits)

    def _sweep(self, now: float) -> None:
        cutoff = now - 1.0
        stale = [ip for ip, hits in self._hits.items() if not hits or hits[-1] <= cutoff]
        for ip in stale:
            del self._hits[ip]


class Gate:
    def __init__(
        self,
        config: Config,
        store: Store,
        abuse: AbuseIPDB | _Checker,
        limiter: RateLimiter | None = None,
        now=None,
        links: Callable[[str], str | None] | None = None,
    ) -> None:
        self.config = config
        self.store = store
        self.abuse = abuse
        self.limiter = limiter or RateLimiter(config.rate_limit_per_sec)
        self.now = now or time.time
        self._links = link_address if links is None else links
        self._guard = threading.Lock()
        self._inflight: dict[str, threading.Lock] = {}

    def note_attempt(self, raw_ip: str) -> Decision | None:
        """Count one connection. A returned decision must be sent before reading."""
        try:
            ip, keys = self._identifiers(raw_ip)
        except ValueError:
            return Decision("reject", 400, "bad_request", "bad_ip")
        if self._exempt(keys):
            return None

        now = float(self.now())
        self._inherit(keys, now)
        _country, rank, _score_limit, rate_cap = self._policy(ip, now)
        worst = 0
        for key in keys:
            worst = max(worst, self.limiter.observe(key, now))
        if worst >= rate_cap:
            days = rate_ban_days(
                worst,
                threshold=rate_cap,
                base_days=self.config.ban_days,
                max_days=self.config.max_ban_days,
            )
            detail = f"rps={worst}"
            if rank:
                detail = f"{detail} country={_country} rank={rank}"
            for key in keys:
                self._ban(key, "rate", days, now, detail, float(worst))
        return self._active(keys, now)

    def decide(self, raw_ip: str, parsed: ParsedRequest | RequestError) -> Decision:
        """Blacklist and format checks for one request that was already counted."""
        try:
            ip, keys = self._identifiers(raw_ip)
        except ValueError:
            return Decision("reject", 400, "bad_request", "bad_ip")
        if self._exempt(keys):
            if isinstance(parsed, RequestError):
                return Decision("reject", parsed.status, "bad_request", parsed.code)
            return Decision("allow", 200, "ok")

        now = float(self.now())
        if self._active(keys, now) is None and self._ensure_reputation(ip, now) == "":
            reputation = self.store.get_reputation(ip, now)
            country, rank, score_limit, _rate_cap = self._policy(ip, now)
            if reputation is not None and reputation.score >= score_limit:
                detail = f"score={reputation.score}"
                if rank:
                    detail = f"{detail} country={country} rank={rank}"
                for key in keys:
                    self._ban(key, "blacklist", self.config.ban_days, now, detail)
        if isinstance(parsed, RequestError):
            self._apply_format(keys, parsed, now)

        active = self._active(keys, now)
        if active is not None:
            return active
        if isinstance(parsed, RequestError):
            return Decision("reject", parsed.status, "bad_request", parsed.code)
        return Decision("allow", 200, "ok")

    def note_format(self, raw_ip: str, parsed: RequestError) -> Decision:
        """Record a body-level format failure without counting another request."""
        try:
            _ip, keys = self._identifiers(raw_ip)
        except ValueError:
            return Decision("reject", 400, "bad_request", "bad_ip")
        if self._exempt(keys):
            return Decision("reject", parsed.status, "bad_request", parsed.code)
        now = float(self.now())
        self._apply_format(keys, parsed, now)
        active = self._active(keys, now)
        if active is not None:
            return active
        return Decision("reject", parsed.status, "bad_request", parsed.code)

    def evaluate(self, raw_ip: str, parsed: ParsedRequest | RequestError) -> Decision:
        """Count the attempt, then apply blacklist and format policy."""
        early = self.note_attempt(raw_ip)
        if early is not None:
            if isinstance(parsed, RequestError):
                try:
                    _ip, keys = self._identifiers(raw_ip)
                except ValueError:
                    return early
                now = float(self.now())
                self._apply_format(keys, parsed, now)
                active = self._active(keys, now)
                if active is not None:
                    return active
            return early
        return self.decide(raw_ip, parsed)

    def _identifiers(self, raw_ip: str) -> tuple[str, tuple[str, ...]]:
        ip = normalize_ip(raw_ip)
        keys = [ip]
        mac = self._mac_for(ip)
        if mac:
            keys.append(mac_key(mac))
        return ip, tuple(keys)

    def _mac_for(self, ip: str) -> str | None:
        try:
            found = self._links(ip)
        except Exception:
            log.warning("mac lookup failed ip=%s", ip)
            return None
        if not found:
            return None
        return normalize_mac(found)

    def _exempt(self, keys: tuple[str, ...]) -> bool:
        return any(key in self.config.whitelist for key in keys)

    def _policy(self, ip: str, now: float) -> tuple[str, str, int, int]:
        """Country, rank, score threshold, and per-second rate cap.

        A missing country keeps the default limits. Private addresses stay there too.
        """
        reputation = self.store.get_reputation(ip, now)
        country = ""
        if reputation is not None and reputation.detail != "private":
            country = reputation.country
        rank = rank_for(country, self.config)
        return country, rank, score_threshold(rank, self.config), rate_limit(rank, self.config)

    def _active(self, keys: tuple[str, ...], now: float) -> Decision | None:
        chosen = None
        for key in keys:
            ban = self.store.get_ban(key, now)
            if ban is None:
                continue
            if chosen is None or ban.expires_at > chosen.expires_at:
                chosen = ban
        if chosen is None:
            return None
        return Decision("block", 403, chosen.reason, chosen.detail, chosen.expires_at)

    def _inherit(self, keys: tuple[str, ...], now: float) -> None:
        found = []
        for key in keys:
            ban = self.store.get_ban(key, now)
            if ban is not None:
                found.append(ban)
        if not found:
            return
        longest = max(found, key=lambda ban: ban.expires_at)
        span = max(0, longest.expires_at - int(now))
        days = max(1, (span + 86399) // 86400)
        for key in keys:
            self._ban(
                key,
                longest.reason,
                days,
                now,
                longest.detail,
                longest.intensity,
                expires_at=longest.expires_at,
            )

    def _ensure_reputation(self, ip: str, now: float) -> str:
        if self.store.get_reputation(ip, now) is not None:
            return ""
        if not is_public(ip):
            self.store.save_reputation(ip, 0, now, self.config.ban_days, "private")
            log.info("reputation ip=%s score=0 private", ip)
            return ""

        with self._guard:
            lock = self._inflight.get(ip)
            if lock is None:
                lock = threading.Lock()
                self._inflight[ip] = lock
        with lock:
            try:
                if self.store.get_reputation(ip, now) is not None:
                    return ""
                result: CheckResult = self.abuse.check(ip)
                if not result.ok:
                    log.warning("abuseipdb unavailable ip=%s detail=%s; local policy", ip, result.error)
                    return result.error or "reputation_unavailable"
                self.store.save_reputation(ip, result.score, now, self.config.ban_days, "", result.country)
                log.info("reputation ip=%s score=%s country=%s", ip, result.score, result.country or "-")
                return ""
            finally:
                with self._guard:
                    current = self._inflight.get(ip)
                    if current is lock:
                        self._inflight.pop(ip, None)

    def _apply_format(self, keys: tuple[str, ...], parsed: RequestError, now: float) -> None:
        if not parsed.ban or self._exempt(keys):
            return
        for key in keys:
            self._ban(key, "format", self.config.ban_days, now, parsed.code)

    def _ban(
        self,
        key: str,
        reason: str,
        days: int,
        now: float,
        detail: str,
        intensity: float | None = None,
        expires_at: int | None = None,
    ) -> None:
        ban, changed = self.store.ban(key, reason, days, now, detail, intensity, expires_at=expires_at)
        if changed:
            log.info(
                "block id=%s reason=%s detail=%s days=%s expires_at=%s",
                key,
                ban.reason,
                ban.detail,
                days,
                ban.expires_at,
            )


class _Checker:
    def check(self, ip: str) -> CheckResult: ...
