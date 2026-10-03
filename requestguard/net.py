"""Peer identifiers the kernel can actually see."""

from __future__ import annotations

import ipaddress
import logging
import re
import subprocess
import threading
import time

log = logging.getLogger("requestguard")

_MAC_KEY = "mac:"
_ARP_AT = re.compile(r"\(([^)]+)\)\s+at\s+(\S+)", re.IGNORECASE)


def normalize_ip(raw: str) -> str:
    text = raw.strip()
    if "%" in text:
        text = text.split("%", 1)[0]
    addr = ipaddress.ip_address(text)
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        addr = mapped
    return str(addr)


def is_public(ip: str) -> bool:
    return ipaddress.ip_address(ip).is_global


def normalize_mac(raw: str) -> str | None:
    parts = raw.strip().lower().replace("-", ":").split(":")
    if len(parts) != 6:
        return None
    try:
        nums = [int(part, 16) for part in parts]
    except ValueError:
        return None
    if any(num > 0xFF for num in nums):
        return None
    if all(num == 0 for num in nums) or all(num == 0xFF for num in nums):
        return None
    return ":".join(f"{num:02x}" for num in nums)


def mac_key(mac: str) -> str:
    return _MAC_KEY + mac


def parse_proc_arp(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        try:
            flags = int(parts[2], 16)
        except ValueError:
            continue
        if flags & 0x2 == 0:
            continue
        _put(found, parts[0], parts[3])
    return found


def parse_ip_neigh(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split()
        if "lladdr" not in parts:
            continue
        if any(flag in parts for flag in ("FAILED", "INCOMPLETE")):
            continue
        index = parts.index("lladdr") + 1
        if index >= len(parts):
            continue
        _put(found, parts[0], parts[index])
    return found


def parse_arp_an(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for match in _ARP_AT.finditer(text):
        _put(found, match.group(1), match.group(2))
    return found


def parse_ndp_an(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[0].lower() == "neighbor":
            continue
        _put(found, parts[0], parts[1])
    return found


def link_address(ip: str) -> str | None:
    """MAC for an on-link peer. Remote clients have no entry."""
    try:
        key = normalize_ip(ip)
    except ValueError:
        return None
    return _NEIGHBORS.get(key)


class _NeighborTable:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._loaded = 0.0
        self._entries: dict[str, str] = {}

    def get(self, ip: str) -> str | None:
        now = time.monotonic()
        with self._lock:
            if now - self._loaded < 1.0:
                return self._entries.get(ip)
        entries = _load_neighbors()
        with self._lock:
            self._entries = entries
            self._loaded = time.monotonic()
            return entries.get(ip)


def _put(found: dict[str, str], raw_ip: str, raw_mac: str) -> None:
    mac = normalize_mac(raw_mac)
    if mac is None:
        return
    try:
        found[normalize_ip(raw_ip)] = mac
    except ValueError:
        return


def _read_text(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


def _run(args: list[str]) -> str:
    try:
        completed = subprocess.run(
            args,
            check=False,
            capture_output=True,
            text=True,
            timeout=0.5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return completed.stdout


def _load_neighbors() -> dict[str, str]:
    found: dict[str, str] = {}
    try:
        proc = _read_text("/proc/net/arp")
        if proc:
            found.update(parse_proc_arp(proc))
            found.update(parse_ip_neigh(_run(["ip", "neigh", "show"])))
            return found
        found.update(parse_arp_an(_run(["arp", "-an"])))
        found.update(parse_ndp_an(_run(["ndp", "-an"])))
        found.update(parse_ip_neigh(_run(["ip", "neigh", "show"])))
    except Exception:
        log.warning("neighbor table unreadable", exc_info=True)
    return found


_NEIGHBORS = _NeighborTable()
