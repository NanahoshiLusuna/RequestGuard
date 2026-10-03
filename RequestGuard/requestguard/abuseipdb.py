"""AbuseIPDB v2 check client."""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from requestguard.country import normalize_country
from requestguard.net import is_public, normalize_ip

log = logging.getLogger("requestguard")

CHECK_URL = "https://api.abuseipdb.com/api/v2/check"


@dataclass(frozen=True)
class CheckResult:
    ok: bool
    score: int = 0
    error: str = ""
    country: str = ""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)


class AbuseIPDB:
    def __init__(self, api_key: str, max_age_days: int, timeout: float) -> None:
        self._api_key = api_key
        self._max_age_days = max(1, min(max_age_days, 30))
        self._timeout = timeout
        self._lock = threading.Lock()
        self._cooldown_until = 0.0
        # The API key must go only to AbuseIPDB. Ignore env proxies and redirects.
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)

    def check(self, ip: str) -> CheckResult:
        try:
            normalized = normalize_ip(ip)
        except ValueError:
            return CheckResult(ok=False, error="bad_ip")
        if not is_public(normalized):
            return CheckResult(ok=False, error="private")

        with self._lock:
            if time.monotonic() < self._cooldown_until:
                return CheckResult(ok=False, error="cooldown")
            return self._check_locked(normalized)

    def _check_locked(self, normalized: str) -> CheckResult:
        query = urllib.parse.urlencode(
            {
                "ipAddress": normalized,
                "maxAgeInDays": str(self._max_age_days),
            }
        )
        request = urllib.request.Request(
            f"{CHECK_URL}?{query}",
            headers={
                "Accept": "application/json",
                "Key": self._api_key,
                "User-Agent": "RequestGuard",
            },
            method="GET",
        )
        try:
            response = self._opener.open(request, timeout=self._timeout)
            try:
                payload = json.loads(response.read().decode("utf-8"))
            finally:
                response.close()
        except urllib.error.HTTPError as exc:
            exc.close()
            log.warning("abuseipdb http_%s", exc.code)
            return self._fail(exc.code, f"http_{exc.code}")
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            log.warning("abuseipdb %s", exc.__class__.__name__)
            return self._fail(0, exc.__class__.__name__)

        data = payload.get("data") if isinstance(payload, dict) else None
        score = data.get("abuseConfidenceScore") if isinstance(data, dict) else None
        if isinstance(score, bool) or not isinstance(score, int):
            return CheckResult(ok=False, error="bad_payload")
        country = normalize_country(data.get("countryCode")) or "XX"
        return CheckResult(ok=True, score=score, country=country)

    def _fail(self, status: int, error: str) -> CheckResult:
        # 401/429 should not be retried on every new IP. Network errors back off briefly.
        delay = 300.0 if status in {401, 403, 429} else 5.0
        self._cooldown_until = time.monotonic() + delay
        return CheckResult(ok=False, error=error)
