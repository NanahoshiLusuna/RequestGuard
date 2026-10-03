"""HTTP/1.1 reverse proxy that applies the gate before the upstream app."""

from __future__ import annotations

import ipaddress
import json
import logging
import resource
import selectors
import socket
import socketserver
import threading
import time

from requestguard.config import Config
from requestguard.gate import Decision, Gate
from requestguard.http_parse import (
    ClientClosed,
    HOP_BY_HOP,
    ParsedRequest,
    RequestError,
    read_body,
    read_head,
)
from requestguard.net import link_address, normalize_ip
from requestguard.ports import interface_ips

log = logging.getLogger("requestguard")

_STATUS = {
    400: "Bad Request",
    403: "Forbidden",
    405: "Method Not Allowed",
    413: "Payload Too Large",
    414: "URI Too Long",
    431: "Request Header Fields Too Large",
    502: "Bad Gateway",
    503: "Service Unavailable",
    505: "HTTP Version Not Supported",
}


class ThreadedServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 128


def build_server(config: Config, gate: Gate) -> ThreadedServer:
    slots = threading.BoundedSemaphore(config.max_connections)
    family = socket.AF_INET6 if ":" in config.listen_host else socket.AF_INET

    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            handle_client(self.request, self.client_address[0], config, gate)

    class Server(ThreadedServer):
        address_family = family

        def server_bind(self) -> None:
            if self.address_family == socket.AF_INET6:
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            super().server_bind()

        def process_request(self, request, client_address) -> None:
            if not slots.acquire(blocking=False):
                try:
                    gate.note_attempt(client_address[0])
                except Exception:
                    log.exception("overload ip=%s", client_address[0])
                finally:
                    self.shutdown_request(request)
                return
            super().process_request(request, client_address)

        def process_request_thread(self, request, client_address) -> None:
            try:
                super().process_request_thread(request, client_address)
            finally:
                slots.release()

    server = Server((config.listen_host, config.listen_port), Handler)
    server.timeout = config.request_timeout
    return server


def serve(config: Config, gate: Gate) -> None:
    _log_policy(config)
    if config.same_port:
        relay = PortRelay(config, gate)
        try:
            relay.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            relay.close()
        return
    server = build_server(config, gate)
    log.info(
        "listen %s:%s upstream %s:%s",
        config.listen_host,
        server.server_address[1],
        config.upstream_host,
        config.upstream_port,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()


def _log_policy(config: Config) -> None:
    log.info(
        "rate %s/s ban %sd max %sd threshold %s",
        config.rate_limit_per_sec,
        config.ban_days,
        config.max_ban_days,
        config.abuse_score_threshold,
    )
    log.info(
        "country trust %s score %s rate %s/s; mixed %s score %s rate %s/s; low score %s rate %s/s",
        ",".join(sorted(config.trust_countries)),
        config.trust_score_threshold,
        config.trust_rate_limit_per_sec,
        ",".join(sorted(config.mixed_countries)),
        config.abuse_score_threshold,
        config.rate_limit_per_sec,
        config.low_score_threshold,
        config.low_rate_limit_per_sec,
    )


def handle_client(sock, raw_ip: str, config: Config, gate: Gate, upstream_port: int | None = None) -> None:
    try:
        ip = normalize_ip(raw_ip)
    except ValueError:
        send_decision(sock, Decision("reject", 400, "bad_request", "bad_ip"))
        _close(sock)
        return
    sock.settimeout(config.request_timeout)
    try:
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        early = gate.note_attempt(ip)
        if early is not None:
            _finish(sock, ip, early)
            return
        try:
            parsed, rest = read_head(sock, config)
        except ClientClosed:
            return
        except RequestError as exc:
            _finish(sock, ip, gate.decide(ip, exc))
            return
        decision = gate.decide(ip, parsed)
        if decision.action != "allow":
            _finish(sock, ip, decision)
            return
        try:
            parsed.body = read_body(sock, parsed, rest, config)
        except RequestError as exc:
            _finish(sock, ip, gate.note_format(ip, exc))
            return
        path = parsed.target.split("?", 1)[0][:200]
        port = _upstream_port(sock, config, upstream_port)
        log.info("allow ip=%s mac=%s %s %s port=%s", ip, link_address(ip) or "-", parsed.method, path, port)
        started = False
        try:
            started = _forward(sock, parsed, ip, config, port)
        except (TimeoutError, socket.timeout, ConnectionError, OSError):
            if not started:
                send_decision(sock, Decision("unavailable", 502, "unavailable", "upstream"))
    except ClientClosed:
        return
    except (TimeoutError, socket.timeout, ConnectionError, OSError):
        return
    except Exception:
        log.exception("request failed ip=%s", ip)
        send_decision(sock, Decision("unavailable", 503, "unavailable", "internal"))
    finally:
        _close(sock)


def _close(sock) -> None:
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def _finish(sock, raw_ip: str, decision: Decision) -> None:
    log.info(
        "deny ip=%s mac=%s status=%s reason=%s detail=%s",
        raw_ip,
        link_address(raw_ip) or "-",
        decision.status,
        decision.reason,
        decision.detail,
    )
    send_decision(sock, decision)


def send_decision(sock, decision: Decision) -> None:
    if decision.action == "block":
        public = decision.reason
    elif decision.action == "unavailable":
        public = "unavailable"
    else:
        public = "bad_request"
    payload: dict[str, object] = {"blocked": decision.action == "block", "reason": public}
    headers = [
        "Content-Type: application/json; charset=utf-8",
        "Connection: close",
        "Cache-Control: no-store",
    ]
    if decision.expires_at is not None:
        payload["expires_at"] = decision.expires_at
        retry_after = max(0, decision.expires_at - int(time.time()))
        headers.append(f"Retry-After: {retry_after}")
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    status = decision.status
    phrase = _STATUS.get(status, "Error")
    head = f"HTTP/1.1 {status} {phrase}\r\n" + "\r\n".join(headers)
    head += f"\r\nContent-Length: {len(body)}\r\n\r\n"
    try:
        sock.sendall(head.encode("ascii") + body)
    except OSError:
        return


def _upstream_port(sock, config: Config, explicit: int | None) -> int:
    if explicit is not None:
        return explicit
    if config.same_port:
        original = _original_port(sock)
        if original:
            return original
        try:
            return int(sock.getsockname()[1])
        except (OSError, IndexError, TypeError):
            pass
    return config.upstream_port


def _original_port(sock) -> int | None:
    try:
        level = socket.SOL_IP if sock.family == socket.AF_INET else socket.IPPROTO_IPV6
        raw = sock.getsockopt(level, 80, 28)
    except (AttributeError, OSError):
        return None
    if len(raw) < 4:
        return None
    port = int.from_bytes(raw[2:4], "big")
    if not 1 <= port <= 65535:
        return None
    return port


def _forward(sock, parsed: ParsedRequest, peer: str, config: Config, port: int) -> bool:
    payload = _build_upstream(parsed, peer, config, port)
    upstream = socket.create_connection((config.upstream_host, port), config.request_timeout)
    started = False
    try:
        upstream.settimeout(config.request_timeout)
        upstream.sendall(payload)
        while True:
            chunk = upstream.recv(65536)
            if not chunk:
                break
            started = True
            sock.sendall(chunk)
    finally:
        upstream.close()
    return started


def _build_upstream(parsed: ParsedRequest, peer: str, config: Config, port: int) -> bytes:
    drop = set(HOP_BY_HOP)
    for value in parsed.header_values("connection"):
        for token in value.split(","):
            name = token.strip().lower()
            if name:
                drop.add(name)
    lines = [f"{parsed.method} {parsed.target} {parsed.version}"]
    has_host = False
    for name, value in parsed.headers:
        if name.lower() in drop or name.lower() in {"x-forwarded-for", "x-forwarded-proto"}:
            continue
        if name.lower() == "host":
            has_host = True
        lines.append(f"{name}: {value}")
    if not has_host:
        host = config.upstream_host
        if port not in {80, 443}:
            host = f"{host}:{port}"
        lines.append(f"Host: {host}")
    if parsed.body or parsed.method not in {"GET", "HEAD", "OPTIONS"}:
        lines.append(f"Content-Length: {len(parsed.body)}")
    lines.append(f"X-Forwarded-For: {peer}")
    lines.append("X-Forwarded-Proto: http")
    lines.append("Connection: close")
    head = "\r\n".join(lines) + "\r\n\r\n"
    return head.encode("latin1") + parsed.body


class PortRelay:
    """Bind the requested ports and forward each one to the same upstream port."""

    def __init__(self, config: Config, gate: Gate) -> None:
        self.config = config
        self.gate = gate
        self.ready = threading.Event()
        self._stop = threading.Event()
        self._slots = threading.BoundedSemaphore(config.max_connections)
        self._socks: list[socket.socket] = []
        self._selector: selectors.BaseSelector | None = None

    def serve_forever(self) -> None:
        bound = self.bind()
        self.ready.set()
        if bound == 0:
            raise SystemExit(
                "열 수 있는 포트가 없습니다. "
                "앱은 127.0.0.1에서만 받고, 이 기기에는 바깥 주소가 있어야 합니다."
            )
        selector = selectors.DefaultSelector()
        self._selector = selector
        for sock in self._socks:
            selector.register(sock, selectors.EVENT_READ)
        try:
            while not self._stop.is_set():
                try:
                    events = selector.select(timeout=0.5)
                except OSError:
                    if self._stop.is_set():
                        return
                    raise
                for key, _mask in events:
                    self._accept(key.fileobj)
        finally:
            selector.close()
            self._selector = None

    def bind(self) -> int:
        hosts = _bind_hosts(self.config)
        if not hosts:
            return 0
        _reject_upstream_overlap(self.config, hosts)
        ports = range(1, 65536) if self.config.listen_all else self.config.listen_ports
        needed = len(hosts) * (65535 if self.config.listen_all else len(ports)) + 256
        _raise_nofile(needed)
        bound = 0
        busy = 0
        for host in hosts:
            for port in ports:
                if self._stop.is_set():
                    return bound
                sock = _listen(host, port)
                if sock is None:
                    busy += 1
                    continue
                self._socks.append(sock)
                bound += 1
        log.info(
            "listen %s port-count %s bound %s busy %s upstream %s:<same>",
            ",".join(hosts),
            "all" if self.config.listen_all else len(ports),
            bound,
            busy,
            self.config.upstream_host,
        )
        return bound

    def close(self) -> None:
        self._stop.set()
        for sock in list(self._socks):
            try:
                sock.close()
            except OSError:
                pass
        self._socks.clear()

    def _accept(self, listen_sock) -> None:
        while not self._stop.is_set():
            try:
                conn, address = listen_sock.accept()
            except BlockingIOError:
                return
            except OSError:
                return
            port = _original_port(conn) or int(listen_sock.getsockname()[1])
            if not self._slots.acquire(blocking=False):
                try:
                    self.gate.note_attempt(address[0])
                except Exception:
                    log.exception("overload ip=%s", address[0])
                finally:
                    conn.close()
                continue
            threading.Thread(
                target=self._run,
                args=(conn, address[0], port),
                daemon=True,
            ).start()

    def _run(self, conn, raw_ip: str, port: int) -> None:
        try:
            handle_client(conn, raw_ip, self.config, self.gate, port)
        finally:
            self._slots.release()


def _bind_hosts(config: Config) -> list[str]:
    host = config.listen_host.strip("[]")
    if host in {"0.0.0.0", "::", "*"}:
        return interface_ips()
    return [host]


def _reject_upstream_overlap(config: Config, hosts: list[str]) -> None:
    name = config.upstream_host.strip("[]")
    try:
        upstream = str(ipaddress.ip_address(name))
    except ValueError:
        return
    if upstream in hosts:
        raise SystemExit(
            "넘기는 주소가 검사 주소와 같습니다. 앱은 127.0.0.1에서만 받으세요."
        )


def _raise_nofile(needed: int) -> None:
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    target = needed if hard == resource.RLIM_INFINITY else min(needed, hard)
    if target <= soft:
        if soft < needed:
            log.warning("nofile soft=%s hard=%s needed=%s", soft, hard, needed)
        return
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
    except (OSError, ValueError):
        log.warning("nofile soft=%s hard=%s needed=%s", soft, hard, needed)


def _listen(host: str, port: int) -> socket.socket | None:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind((host, port))
        sock.listen(128)
        sock.setblocking(False)
    except OSError:
        sock.close()
        return None
    return sock
