"""Country ranks for public IPs.

Korea and Japan are trusted, the United States stays on the default limits,
and every other country is held to the strict limits.
"""

from __future__ import annotations

from requestguard.config import Config


def normalize_country(raw: object) -> str:
    if not isinstance(raw, str):
        return ""
    text = raw.strip().upper()
    if len(text) == 2 and text.isalpha():
        return text
    return ""


def rank_for(country: str, config: Config) -> str:
    """Return trust, mixed, low, or '' when the country is still unknown."""
    if not country:
        return ""
    if country in config.trust_countries:
        return "trust"
    if country in config.mixed_countries:
        return "mixed"
    return "low"


def score_threshold(rank: str, config: Config) -> int:
    if rank == "trust":
        return config.trust_score_threshold
    if rank == "low":
        return config.low_score_threshold
    return config.abuse_score_threshold


def rate_limit(rank: str, config: Config) -> int:
    if rank == "trust":
        return config.trust_rate_limit_per_sec
    if rank == "low":
        return config.low_rate_limit_per_sec
    return config.rate_limit_per_sec
