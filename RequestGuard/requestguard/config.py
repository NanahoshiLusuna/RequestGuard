"""Environment configuration."""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass

from requestguard.net import mac_key, normalize_ip, normalize_mac


def load_env_file(path: str) -> None:
    if not os.path.isfile(path):
        return
    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
                value = value[1:-1]
            if key and key not in os.environ:
                os.environ[key] = value


def load_env_files() -> None:
    load_env_file(os.path.join(os.getcwd(), "requestguard.env"))
    package_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    load_env_file(os.path.join(package_root, "requestguard.env"))


def _env_int(name: str, default: int, *, low: int, high: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        value = default
    else:
        try:
            value = int(raw)
        except ValueError as exc:
            raise SystemExit(f"{name}은 정수여야 합니다.") from exc
    if not low <= value <= high:
        raise SystemExit(f"{name}은 {low}에서 {high} 사이여야 합니다.")
    return value


def _forwards_to_self(listen_host: str, listen_port: int, upstream_host: str, upstream_port: int) -> bool:
    """True when the proxy would connect back to its own listener."""
    if listen_port != upstream_port:
        return False
    upstream_name = upstream_host.strip("[]").lower()
    if upstream_name == "localhost":
        return True
    try:
        upstream = ipaddress.ip_address(upstream_name)
    except ValueError:
        return False
    if upstream.is_loopback or upstream.is_unspecified:
        return True
    try:
        listen = ipaddress.ip_address(listen_host.strip("[]"))
    except ValueError:
        return False
    return listen == upstream


def _listen_ports() -> tuple[bool, tuple[int, ...], bool]:
    raw = os.environ.get("LISTEN_PORTS", "").strip()
    if not raw:
        return False, (), False
    if raw.lower() == "all":
        return True, (), True
    from requestguard.ports import parse_ports

    return False, parse_ports(raw), True


def _loopback_name(host: str) -> bool:
    name = host.strip("[]").lower()
    if name == "localhost":
        return True
    try:
        return ipaddress.ip_address(name).is_loopback
    except ValueError:
        return False


def _countries(name: str, default: str) -> frozenset[str]:
    raw = os.environ.get(name, "").strip() or default
    found: list[str] = []
    for part in raw.split(","):
        item = part.strip().upper()
        if not item:
            continue
        if len(item) != 2 or not item.isalpha():
            raise SystemExit(f"{name}에 잘못된 국가 코드가 있습니다: {item}")
        found.append(item)
    return frozenset(found)


def _whitelist(raw: str) -> frozenset[str]:
    found: list[str] = []
    for part in raw.split(","):
        item = part.strip()
        if not item:
            continue
        mac = normalize_mac(item)
        if mac:
            found.append(mac_key(mac))
            continue
        try:
            found.append(normalize_ip(item))
        except ValueError as exc:
            raise SystemExit(f"WHITELIST에 잘못된 IP 또는 MAC이 있습니다: {item}") from exc
    return frozenset(found)


@dataclass(frozen=True)
class Config:
    api_key: str
    listen_host: str = "0.0.0.0"
    listen_port: int = 8080
    upstream_host: str = "127.0.0.1"
    upstream_port: int = 3000
    listen_all: bool = False
    listen_ports: tuple[int, ...] = ()
    same_port: bool = False
    abuse_score_threshold: int = 75
    abuse_max_age_days: int = 30
    ban_days: int = 30
    max_ban_days: int = 365
    rate_limit_per_sec: int = 30
    trust_countries: frozenset[str] = frozenset({"JP", "KR"})
    mixed_countries: frozenset[str] = frozenset({"US"})
    trust_score_threshold: int = 90
    trust_rate_limit_per_sec: int = 60
    low_score_threshold: int = 25
    low_rate_limit_per_sec: int = 10
    whitelist: frozenset[str] = frozenset()
    db_path: str = "data/requestguard.db"
    request_timeout: float = 15.0
    abuse_timeout: float = 5.0
    max_connections: int = 64
    max_header_bytes: int = 32 * 1024
    max_header_line: int = 8 * 1024
    max_headers: int = 100
    max_target_bytes: int = 8 * 1024
    max_body_bytes: int = 1024 * 1024
    absurd_body_bytes: int = 32 * 1024 * 1024
    max_dotdot: int = 0

    @classmethod
    def from_env(cls) -> Config:
        api_key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
        if not api_key:
            raise SystemExit(
                "ABUSEIPDB_API_KEY가 없습니다. "
                "https://www.abuseipdb.com/account/api 에서 발급한 키를 requestguard.env에 넣으세요. "
                "가입 확인 링크는 API 키가 아닙니다."
            )
        if api_key.startswith(("http://", "https://")):
            raise SystemExit(
                "ABUSEIPDB_API_KEY에는 가입 확인 링크가 아니라 "
                "계정 API 페이지에서 발급한 키를 넣으세요."
            )

        ban_days = _env_int("BAN_DAYS", 30, low=1, high=3650)
        max_ban_days = _env_int("MAX_BAN_DAYS", 365, low=ban_days, high=3650)
        trust_countries = _countries("TRUST_COUNTRIES", "KR,JP")
        mixed_countries = _countries("MIXED_COUNTRIES", "US")
        overlap = trust_countries & mixed_countries
        if overlap:
            names = ", ".join(sorted(overlap))
            raise SystemExit(f"TRUST_COUNTRIES와 MIXED_COUNTRIES에 같은 국가가 있습니다: {names}")
        abuse_max_age = min(ban_days, 30)
        listen_host = os.environ.get("LISTEN_HOST", "0.0.0.0").strip() or "0.0.0.0"
        listen_port = _env_int("LISTEN_PORT", 8080, low=1, high=65535)
        upstream_host = os.environ.get("UPSTREAM_HOST", "127.0.0.1").strip() or "127.0.0.1"
        upstream_port = _env_int("UPSTREAM_PORT", 3000, low=1, high=65535)
        listen_all, listen_ports, same_port = _listen_ports()
        if same_port and _loopback_name(listen_host):
            raise SystemExit(
                "같은 포트로 넘기려면 수신 주소를 127.0.0.1로 두면 안 됩니다. "
                "앱만 127.0.0.1에서 받으세요."
            )
        if not same_port and _forwards_to_self(listen_host, listen_port, upstream_host, upstream_port):
            raise SystemExit(
                "프록시가 자기 자신으로 요청을 넘깁니다. "
                "앱은 다른 포트에서만 받고, 이 프록시 포트만 바깥에 여세요."
            )
        return cls(
            api_key=api_key,
            listen_host=listen_host,
            listen_port=listen_port,
            upstream_host=upstream_host,
            upstream_port=upstream_port,
            listen_all=listen_all,
            listen_ports=listen_ports,
            same_port=same_port,
            abuse_score_threshold=_env_int("ABUSE_SCORE_THRESHOLD", 75, low=0, high=100),
            abuse_max_age_days=abuse_max_age,
            ban_days=ban_days,
            max_ban_days=max_ban_days,
            rate_limit_per_sec=_env_int("RATE_LIMIT_PER_SEC", 30, low=1, high=100000),
            trust_countries=trust_countries,
            mixed_countries=mixed_countries,
            trust_score_threshold=_env_int("TRUST_SCORE_THRESHOLD", 90, low=0, high=100),
            trust_rate_limit_per_sec=_env_int("TRUST_RATE_LIMIT_PER_SEC", 60, low=1, high=100000),
            low_score_threshold=_env_int("LOW_SCORE_THRESHOLD", 25, low=0, high=100),
            low_rate_limit_per_sec=_env_int("LOW_RATE_LIMIT_PER_SEC", 10, low=1, high=100000),
            whitelist=_whitelist(os.environ.get("WHITELIST", "")),
            db_path=os.environ.get("DB_PATH", "data/requestguard.db").strip() or "data/requestguard.db",
            request_timeout=float(os.environ.get("REQUEST_TIMEOUT", "15") or "15"),
            abuse_timeout=float(os.environ.get("ABUSE_TIMEOUT", "5") or "5"),
            max_connections=_env_int("MAX_CONNECTIONS", 64, low=1, high=10000),
        )
