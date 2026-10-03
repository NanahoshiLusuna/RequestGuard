"""Proxy ordering: screen the IP before reading a body, then forward a clean request."""

import socket
import socketserver
import threading
import time
import unittest

from requestguard.abuseipdb import CheckResult
from requestguard.config import Config
from requestguard.gate import Gate
from requestguard.proxy import PortRelay, build_server, handle_client
from requestguard.store import Store


class FakeAbuse:
    def __init__(self, score: int = 0, error: str = "") -> None:
        self.score = score
        self.error = error
        self.calls: list[str] = []

    def check(self, ip: str) -> CheckResult:
        self.calls.append(ip)
        if self.error:
            return CheckResult(ok=False, error=self.error)
        return CheckResult(ok=True, score=self.score)


class _Upstream(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self) -> None:
        self.seen: list[bytes] = []
        self._seen_lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), _UpstreamHandler)


class _UpstreamHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server: _Upstream = self.server  # type: ignore[assignment]
        self.request.settimeout(2)
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = self.request.recv(4096)
            if not chunk:
                return
            data += chunk
        head, rest = data.split(b"\r\n\r\n", 1)
        length = 0
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                length = int(line.split(b":", 1)[1].strip())
        while len(rest) < length:
            chunk = self.request.recv(4096)
            if not chunk:
                break
            rest += chunk
        with server._seen_lock:
            server.seen.append(head + b"\r\n\r\n" + rest[:length])
        self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")


def _serve(gate: Gate, upstream_port: int, timeout: float = 2):
    cfg = Config(
        api_key="test-key",
        listen_host="127.0.0.1",
        listen_port=0,
        upstream_host="127.0.0.1",
        upstream_port=upstream_port,
        request_timeout=timeout,
    )
    server = build_server(cfg, gate)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return cfg, server, thread


def _exchange(addr, payload: bytes) -> bytes:
    last: Exception | None = None
    sock = None
    for _ in range(50):
        try:
            sock = socket.create_connection(addr, timeout=2)
            break
        except OSError as exc:
            last = exc
            time.sleep(0.02)
    if sock is None:
        raise last or OSError("connect failed")
    try:
        sock.sendall(payload)
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        return data
    finally:
        sock.close()


class ProxyTest(unittest.TestCase):
    def test_live_proxy_forwards_private_client_and_strips_forwarded_for(self) -> None:
        upstream = _Upstream()
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()
        abuse = FakeAbuse()
        store = Store(":memory:")
        gate = Gate(Config(api_key="test-key"), store, abuse)
        _cfg, server, thread = _serve(gate, upstream.server_address[1])
        try:
            response = _exchange(
                ("127.0.0.1", server.server_address[1]),
                b"POST /hi?x=1 HTTP/1.1\r\nHost: t\r\nX-Forwarded-For: 1.2.3.4\r\nContent-Length: 5\r\n\r\nhello",
            )
            self.assertIn(b"200", response)
            self.assertTrue(response.endswith(b"ok"))
            self.assertEqual(len(upstream.seen), 1)
            seen = upstream.seen[0]
            self.assertIn(b"X-Forwarded-For: 127.0.0.1", seen)
            self.assertNotIn(b"1.2.3.4", seen)
            self.assertIn(b"hello", seen)
            self.assertEqual(abuse.calls, [])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)
            upstream.shutdown()
            upstream.server_close()
            upstream_thread.join(2)
            store.close()

    def test_live_proxy_bans_hostile_format(self) -> None:
        abuse = FakeAbuse()
        store = Store(":memory:")
        gate = Gate(Config(api_key="test-key"), store, abuse)
        _cfg, server, thread = _serve(gate, 9)
        try:
            first = _exchange(("127.0.0.1", server.server_address[1]), b"\x00\r\n\r\n")
            second = _exchange(
                ("127.0.0.1", server.server_address[1]),
                b"GET / HTTP/1.1\r\nHost: t\r\n\r\n",
            )
            self.assertIn(b"403", first)
            self.assertIn(b'"reason":"format"', first)
            self.assertIn(b"403", second)
            self.assertEqual(abuse.calls, [])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)
            store.close()

    def test_public_blacklist_answers_before_the_body(self) -> None:
        abuse = FakeAbuse(score=99)
        store = Store(":memory:")
        cfg = Config(
            api_key="test-key",
            listen_host="127.0.0.1",
            upstream_host="127.0.0.1",
            upstream_port=1,
            request_timeout=1,
        )
        gate = Gate(cfg, store, abuse)
        try:
            first = _pair_request(
                cfg,
                gate,
                "8.8.8.8",
                b"POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 1000000\r\n\r\n",
            )
            self.assertLess(first[0], 0.8)
            self.assertIn(b"403", first[1])
            self.assertIn(b'"reason":"blacklist"', first[1])
            self.assertEqual(abuse.calls, ["8.8.8.8"])
            second = _pair_request(cfg, gate, "8.8.8.8", b"")
            self.assertLess(second[0], 0.8)
            self.assertIn(b"403", second[1])
            self.assertEqual(abuse.calls, ["8.8.8.8"])
        finally:
            store.close()

    def test_public_request_forwards_the_checked_ip(self) -> None:
        upstream = _Upstream()
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()
        abuse = FakeAbuse(score=0)
        store = Store(":memory:")
        cfg = Config(
            api_key="test-key",
            upstream_host="127.0.0.1",
            upstream_port=upstream.server_address[1],
            request_timeout=2,
        )
        gate = Gate(cfg, store, abuse)
        try:
            elapsed, response = _pair_request(
                cfg,
                gate,
                "8.8.8.8",
                b"POST /hi HTTP/1.1\r\nHost: t\r\nX-Forwarded-For: 1.2.3.4\r\nContent-Length: 5\r\n\r\nhello",
            )
            self.assertLess(elapsed, 2)
            self.assertIn(b"200", response)
            self.assertEqual(abuse.calls, ["8.8.8.8"])
            self.assertEqual(len(upstream.seen), 1)
            self.assertIn(b"X-Forwarded-For: 8.8.8.8", upstream.seen[0])
            self.assertNotIn(b"1.2.3.4", upstream.seen[0])
            _elapsed, again = _pair_request(
                cfg,
                gate,
                "8.8.8.8",
                b"GET / HTTP/1.1\r\nHost: t\r\n\r\n",
            )
            self.assertIn(b"200", again)
            self.assertEqual(abuse.calls, ["8.8.8.8"])
        finally:
            upstream.shutdown()
            upstream.server_close()
            upstream_thread.join(2)
            store.close()

    def test_same_port_relays_ipv6_listener_to_ipv4_localhost(self) -> None:
        upstream = _Upstream()
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()
        port = upstream.server_address[1]
        abuse = FakeAbuse()
        store = Store(":memory:")
        cfg = Config(
            api_key="test-key",
            listen_host="::1",
            listen_ports=(port,),
            same_port=True,
            upstream_host="127.0.0.1",
            upstream_port=9,
            request_timeout=2,
        )
        gate = Gate(cfg, store, abuse)
        relay = PortRelay(cfg, gate)
        thread = threading.Thread(target=relay.serve_forever, daemon=True)
        thread.start()
        try:
            self.assertTrue(relay.ready.wait(2))
            response = _exchange(("::1", port), b"GET /hi HTTP/1.1\r\nHost: t\r\n\r\n")
            self.assertIn(b"200", response)
            self.assertEqual(len(upstream.seen), 1)
            self.assertIn(b"GET /hi", upstream.seen[0])
            self.assertIn(b"X-Forwarded-For: ::1", upstream.seen[0])
        finally:
            relay.close()
            thread.join(2)
            upstream.shutdown()
            upstream.server_close()
            upstream_thread.join(2)
            store.close()

    def test_api_failure_forwards_without_a_local_ban(self) -> None:
        upstream = _Upstream()
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()
        abuse = FakeAbuse(error="http_401")
        store = Store(":memory:")
        cfg = Config(
            api_key="test-key",
            upstream_host="127.0.0.1",
            upstream_port=upstream.server_address[1],
            request_timeout=2,
        )
        gate = Gate(cfg, store, abuse)
        try:
            _elapsed, response = _pair_request(
                cfg,
                gate,
                "8.8.8.8",
                b"GET / HTTP/1.1\r\nHost: t\r\n\r\n",
            )
            self.assertIn(b"200", response)
            self.assertEqual(abuse.calls, ["8.8.8.8"])
            self.assertEqual(len(upstream.seen), 1)
            self.assertIsNone(store.get_ban("8.8.8.8", time.time()))
            banned = _pair_request(
                cfg,
                gate,
                "8.8.8.8",
                b"\x00\r\n\r\n",
            )
            self.assertIn(b"403", banned[1])
            self.assertIn(b'"reason":"format"', banned[1])
            self.assertEqual(len(upstream.seen), 1)
        finally:
            upstream.shutdown()
            upstream.server_close()
            upstream_thread.join(2)
            store.close()


def _read_response(sock) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            return data
        data += chunk
    head, rest = data.split(b"\r\n\r\n", 1)
    length = 0
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1].strip())
    while len(rest) < length:
        chunk = sock.recv(4096)
        if not chunk:
            break
        rest += chunk
    return head + b"\r\n\r\n" + rest[:length]


def _pair_request(cfg: Config, gate: Gate, ip: str, payload: bytes) -> tuple[float, bytes]:
    client, remote = socket.socketpair()
    client.settimeout(2)
    worker = threading.Thread(target=handle_client, args=(remote, ip, cfg, gate))
    started = time.monotonic()
    worker.start()
    try:
        if payload:
            client.sendall(payload)
        data = _read_response(client)
        return time.monotonic() - started, data
    finally:
        client.close()
        worker.join(3)


if __name__ == "__main__":
    unittest.main()
