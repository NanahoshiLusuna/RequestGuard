"""Listen addresses and port lists for same-port forwarding."""

from __future__ import annotations

import ctypes
import ctypes.util
import ipaddress
import socket
import sys

def parse_ports(raw: str) -> tuple[int, ...]:
    """Parse '80,443,8000-8002'. 'all' is handled by the caller."""
    found: list[int] = []
    seen: set[int] = set()
    for part in raw.split(","):
        item = part.strip()
        if not item:
            continue
        if "-" in item:
            left, right = item.split("-", 1)
            start = _port(left)
            end = _port(right)
            if end < start:
                raise SystemExit(f"포트 범위가 뒤집혀 있습니다: {item}")
            values = range(start, end + 1)
        else:
            values = (_port(item),)
        for port in values:
            if port not in seen:
                seen.add(port)
                found.append(port)
    if not found:
        raise SystemExit("LISTEN_PORTS에 포트가 없습니다.")
    return tuple(found)


def interface_ips() -> list[str]:
    """Non-loopback unicast addresses. Loopback stays free for the apps."""
    records = _interfaces()
    chosen: list[str] = []
    seen: set[str] = set()
    for flags, ip in records:
        if flags & 0x8:  # IFF_LOOPBACK
            continue
        if not ip or ip in seen:
            continue
        if not _usable(ip):
            continue
        seen.add(ip)
        chosen.append(ip)
    v4 = [ip for ip in chosen if ":" not in ip]
    v6 = [ip for ip in chosen if ":" in ip]
    return v4 + v6


def _port(raw: str) -> int:
    try:
        port = int(raw.strip())
    except ValueError as exc:
        raise SystemExit(f"포트는 정수여야 합니다: {raw}") from exc
    if not 1 <= port <= 65535:
        raise SystemExit(f"포트는 1에서 65535 사이여야 합니다: {port}")
    return port


def _usable(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return False
    return not (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
        or addr.is_reserved
    )


def _interfaces() -> list[tuple[int, str | None]]:
    libc_name = ctypes.util.find_library("c")
    if not libc_name:
        return []
    libc = ctypes.CDLL(libc_name, use_errno=True)
    libc.getifaddrs.argtypes = [ctypes.POINTER(ctypes.POINTER(_ifaddrs))]
    libc.freeifaddrs.argtypes = [ctypes.POINTER(_ifaddrs)]
    head = ctypes.POINTER(_ifaddrs)()
    if libc.getifaddrs(ctypes.byref(head)) != 0:
        return []
    found: list[tuple[int, str | None]] = []
    try:
        ptr = head
        while ptr:
            item = ptr.contents
            ip = None
            if item.ifa_addr:
                raw = ctypes.string_at(item.ifa_addr, 32)
                ip = _sockaddr_ip(raw)
            found.append((int(item.ifa_flags), ip))
            ptr = item.ifa_next
    finally:
        libc.freeifaddrs(head)
    return found


class _ifaddrs(ctypes.Structure):
    pass


_ifaddrs._fields_ = [
    ("ifa_next", ctypes.POINTER(_ifaddrs)),
    ("ifa_name", ctypes.c_char_p),
    ("ifa_flags", ctypes.c_uint),
    ("ifa_addr", ctypes.c_void_p),
    ("ifa_netmask", ctypes.c_void_p),
    ("ifa_ifu", ctypes.c_void_p),
    ("ifa_data", ctypes.c_void_p),
]


def _sockaddr_ip(raw: bytes) -> str | None:
    if sys.platform == "linux":
        family = int.from_bytes(raw[:2], sys.byteorder)
    else:
        family = raw[1]
    if family == socket.AF_INET:
        return str(ipaddress.IPv4Address(raw[4:8]))
    if family == socket.AF_INET6:
        return str(ipaddress.IPv6Address(raw[8:24]))
    return None
