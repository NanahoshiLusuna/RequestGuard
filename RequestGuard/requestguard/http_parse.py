"""Strict HTTP/1.x request reader.

Hostile framing is marked for a stored ban. Ordinary client mistakes are rejected
for that request only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from requestguard.config import Config

_METHOD = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,32}\Z")
_HEADER_NAME = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+\Z")
_HEX = frozenset("0123456789abcdefABCDEF")

HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "proxy-connection",
        "content-length",
    }
)


class ClientClosed(Exception):
    pass


class RequestError(Exception):
    def __init__(self, code: str, ban: bool, status: int = 400) -> None:
        super().__init__(code)
        self.code = code
        self.ban = ban
        self.status = status


@dataclass
class ParsedRequest:
    method: str
    target: str
    version: str
    headers: list[tuple[str, str]]
    body: bytes = field(default_factory=bytes)

    def header_values(self, name: str) -> list[str]:
        needle = name.lower()
        return [value for key, value in self.headers if key.lower() == needle]


def read_head(sock, config: Config) -> tuple[ParsedRequest, bytes]:
    """Read one HTTP head. Body bytes already in the same packet are returned, not fetched."""
    buf = bytearray()
    limit = config.max_header_bytes
    while b"\r\n\r\n" not in buf:
        if b"\n\n" in buf and b"\r" not in buf:
            raise RequestError("lf_only", False, 400)
        chunk = sock.recv(4096)
        if not chunk:
            if not buf:
                raise ClientClosed()
            if b"\x00" in buf:
                raise RequestError("nul", True, 400)
            raise RequestError("truncated", False, 400)
        buf += chunk
        if b"\r\n\r\n" in buf:
            break
        if b"\x00" in buf:
            raise RequestError("nul", True, 400)
        if len(buf) > limit:
            raise RequestError("headers_too_large", True, 431)

    raw = bytes(buf)
    head, rest = raw.split(b"\r\n\r\n", 1)
    if b"\x00" in head:
        raise RequestError("nul", True, 400)
    if len(head) > limit:
        raise RequestError("headers_too_large", True, 431)
    return parse_head(head, config), rest


def read_body(sock, parsed: ParsedRequest, rest: bytes, config: Config) -> bytes:
    return _read_body(sock, parsed, rest, config)


def read_request(sock, config: Config) -> ParsedRequest:
    parsed, rest = read_head(sock, config)
    parsed.body = read_body(sock, parsed, rest, config)
    return parsed


def parse_request_bytes(data: bytes, config: Config) -> ParsedRequest:
    class _Reader:
        def __init__(self, payload: bytes) -> None:
            self._payload = payload
            self._offset = 0

        def recv(self, size: int) -> bytes:
            if self._offset >= len(self._payload):
                return b""
            chunk = self._payload[self._offset : self._offset + size]
            self._offset += len(chunk)
            return chunk

    return read_request(_Reader(data), config)


def parse_head(head: bytes, config: Config) -> ParsedRequest:
    try:
        text = head.decode("latin1")
    except UnicodeError as exc:
        raise RequestError("bad_encoding", True, 400) from exc

    lines = text.split("\r\n")
    if not lines or lines[0] == "":
        raise RequestError("bad_request_line", True, 400)
    if len(lines[0]) > config.max_header_line:
        raise RequestError("line_too_long", True, 400)
    for line in lines[1:]:
        if len(line) > config.max_header_line:
            raise RequestError("line_too_long", True, 400)
        if line[:1] in {" ", "\t"}:
            raise RequestError("header_fold", True, 400)

    method, target, version = _request_line(lines[0])
    if len(lines) - 1 > config.max_headers:
        raise RequestError("too_many_headers", True, 431)

    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if line == "":
            continue
        name, separator, value = line.partition(":")
        if separator == "" or not _HEADER_NAME.fullmatch(name):
            raise RequestError("bad_header", True, 400)
        if any((ord(ch) < 0x20 and ch != "\t") or ord(ch) == 0x7F for ch in value):
            raise RequestError("control_char", True, 400)
        if value.startswith(" "):
            value = value[1:]
        headers.append((name, value.rstrip(" \t")))

    parsed = ParsedRequest(method=method, target=target, version=version, headers=headers)
    _reject_hostile_shape(parsed, config)
    return parsed


def _request_line(line: str) -> tuple[str, str, str]:
    parts = line.split(" ")
    if len(parts) != 3 or any(part == "" for part in parts):
        raise RequestError("bad_request_line", True, 400)
    method, target, version = parts
    if not _METHOD.fullmatch(method):
        raise RequestError("bad_method", True, 400)
    if version not in {"HTTP/1.0", "HTTP/1.1"}:
        if re.fullmatch(r"HTTP/\d\.\d", version):
            raise RequestError("unsupported_version", False, 505)
        raise RequestError("bad_version", True, 400)
    return method, target, version


def _reject_hostile_shape(parsed: ParsedRequest, config: Config) -> None:
    if parsed.method == "CONNECT":
        raise RequestError("connect", True, 405)
    target = parsed.target
    if len(target.encode("latin1")) > config.max_target_bytes:
        raise RequestError("target_too_long", True, 414)
    if parsed.method == "OPTIONS" and target == "*":
        pass
    elif target.startswith(("http://", "https://")):
        raise RequestError("absolute_form", True, 400)
    elif not target.startswith("/"):
        raise RequestError("bad_target", True, 400)
    else:
        if "\\" in target:
            raise RequestError("backslash", True, 400)
        _inspect_target(target, config.max_dotdot)

    hosts = parsed.header_values("host")
    if len(hosts) > 1:
        raise RequestError("duplicate_host", True, 400)
    if parsed.version == "HTTP/1.1" and not hosts:
        raise RequestError("missing_host", False, 400)

    lengths = parsed.header_values("content-length")
    codings = parsed.header_values("transfer-encoding")
    if lengths and codings:
        raise RequestError("cl_te", True, 400)
    if len(lengths) > 1:
        raise RequestError("duplicate_cl", True, 400)
    if lengths:
        _content_length(lengths[0], config)
    if codings:
        found: list[str] = []
        for raw in codings:
            for part in raw.split(","):
                coding = part.split(";", 1)[0].strip().lower()
                if coding:
                    found.append(coding)
        if found != ["chunked"]:
            raise RequestError("bad_transfer_encoding", True, 400)


def _content_length(raw: str, config: Config) -> int:
    text = raw.strip()
    if len(text) > 10 or not text.isdigit():
        raise RequestError("bad_content_length", True, 400)
    length = int(text)
    if length > config.absurd_body_bytes:
        raise RequestError("absurd_body", True, 413)
    if length > config.max_body_bytes:
        raise RequestError("body_too_large", False, 413)
    return length


def _inspect_target(target: str, max_dotdot: int) -> None:
    decoded = bytearray()
    index = 0
    while index < len(target):
        char = target[index]
        if char == "%":
            hexpart = target[index + 1 : index + 3]
            if len(hexpart) < 2 or any(item not in _HEX for item in hexpart):
                raise RequestError("bad_percent", True, 400)
            value = int(hexpart, 16)
            if value == 0:
                raise RequestError("encoded_nul", True, 400)
            decoded.append(value)
            index += 3
            continue
        code = ord(char)
        if code < 0x20 or code == 0x7F:
            raise RequestError("control_char", True, 400)
        decoded.append(code)
        index += 1

    path = decoded.decode("latin1").split("?", 1)[0]
    dotdot = sum(1 for segment in path.split("/") if segment == "..")
    if dotdot > max_dotdot:
        raise RequestError("traversal", True, 400)


def _read_body(sock, parsed: ParsedRequest, rest: bytes, config: Config) -> bytes:
    if parsed.header_values("transfer-encoding"):
        return _read_chunked(sock, rest, config.max_body_bytes)
    lengths = parsed.header_values("content-length")
    if not lengths:
        return b""
    length = _content_length(lengths[0], config)
    buf = bytearray(rest)
    while len(buf) < length:
        chunk = sock.recv(min(65536, length - len(buf)))
        if not chunk:
            raise RequestError("truncated_body", False, 400)
        buf += chunk
    return bytes(buf[:length])


def _readline(buf: bytearray, sock, limit: int) -> bytes:
    while b"\r\n" not in buf:
        if len(buf) > limit:
            raise RequestError("bad_chunk", True, 400)
        chunk = sock.recv(4096)
        if not chunk:
            raise RequestError("bad_chunk", True, 400)
        buf += chunk
    line, separator, rest = bytes(buf).partition(b"\r\n")
    if separator != b"\r\n":
        raise RequestError("bad_chunk", True, 400)
    buf[:] = rest
    if len(line) > limit:
        raise RequestError("bad_chunk", True, 400)
    return line


def _read_exact(buf: bytearray, sock, size: int, ceiling: int) -> bytes:
    while len(buf) < size:
        chunk = sock.recv(min(65536, size - len(buf)))
        if not chunk:
            raise RequestError("bad_chunk", True, 400)
        buf += chunk
        if len(buf) > ceiling:
            raise RequestError("absurd_body", True, 413)
    got = bytes(buf[:size])
    del buf[:size]
    return got


def _read_chunked(sock, rest: bytes, max_body: int) -> bytes:
    buf = bytearray(rest)
    body = bytearray()
    ceiling = max_body + 8192
    while True:
        line = _readline(buf, sock, 4096)
        token = line.split(b";", 1)[0].strip()
        if not token or any(chr(item) not in "0123456789abcdefABCDEF" for item in token):
            raise RequestError("bad_chunk", True, 400)
        size = int(token, 16)
        if size == 0:
            while _readline(buf, sock, 8192) != b"":
                continue
            return bytes(body)
        if len(body) + size > max_body:
            raise RequestError("body_too_large", False, 413)
        data = _read_exact(buf, sock, size + 2, ceiling)
        if not data.endswith(b"\r\n"):
            raise RequestError("bad_chunk", True, 400)
        body += data[:-2]
