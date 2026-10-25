"""The sandbox gateway: Lure's own egress proxy and logging DNS responder.

Runs in its own container, the only one with a leg on a network that can
reach outside. The agent's container sits on an internal network with no
default route, so the gateway is the only place its traffic can go.

Listeners, all on the gateway's internal address:

  3128/tcp  explicit proxy (HTTPS_PROXY, HTTP_PROXY): CONNECT host:port, or
            an absolute-form http:// request
  443/tcp   TLS passthrough, decided by the ClientHello's server name (SNI)
  80/tcp    plain HTTP, decided by the Host header
  53/udp    DNS: an allowed name resolves to the gateway itself (so a client
            that ignores the proxy settings still lands on 443 or 80 here);
            every other name gets NXDOMAIN

A connection goes on only when its host and port are on the allowlist
(exact host names, no wildcards). Everything else is refused and logged.
TLS is never decrypted: the gateway decides from the CONNECT line or the
SNI and then copies bytes. An IP literal is blocked unless listed as is.

Every decision is one JSON line on stdout (`event`: ready, egress, dns),
which Lure reads back with `docker logs` after the run. Nothing is written
to disk.

Limits: the gateway trusts the name a client presents. A client could
present an allowed name in SNI and ask the allowed host for something else
inside TLS (domain fronting); that reaches only the allowed host's servers.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import selectors
import socket
import socketserver
import sys
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from lure.sandbox import dns, sni

PROXY_PORT = 3128
HTTP_PORT = 80
TLS_PORT = 443
DNS_PORT = 53
MAX_HEAD = 16384
HEAD_TIMEOUT = 10.0
CONNECT_TIMEOUT = 10.0
# A model's streamed answer can pause; an idle tunnel closes after this.
IDLE_TIMEOUT = 300.0
CHUNK = 65536
BLOCKED = "not on the allowlist"
UNREADABLE = "(unreadable)"
HOP_HEADERS = ("proxy-connection", "proxy-authorization", "connection", "keep-alive")

_lock = threading.Lock()


def _now() -> str:
    return datetime.now(UTC).isoformat()


def emit(event: dict[str, Any], out=None) -> None:
    """One event as a JSON line on stdout."""
    line = json.dumps({"at": _now(), **event}, sort_keys=True)
    with _lock:
        print(line, file=out or sys.stdout, flush=True)


@dataclass(frozen=True)
class Allowlist:
    """Allowed (host, port) pairs. A host given without a port allows 443.

    An entry may end in a path prefix (host:port/api/chat). Such a host is
    reachable only over plain HTTP, where the gateway reads the request
    path, and only for paths under a listed prefix: CONNECT and SNI to it
    are refused, as a tunnel would hide the path. This keeps an agent on a
    local model's chat endpoint and away from the rest of its API (for
    Ollama: pull, delete, create)."""

    entries: frozenset[tuple[str, int]]
    # (host, port) -> allowed path prefixes; missing means any path.
    paths: tuple[tuple[tuple[str, int], tuple[str, ...]], ...] = ()

    @classmethod
    def parse(cls, items: Iterable[str]) -> Allowlist:
        found, paths = set(), {}
        for item in items:
            text = item.strip()
            authority, slash, path = text.partition("/")
            host, port = split_host_port(authority, TLS_PORT)
            if not host or port == 0:
                raise ValueError(f"bad allowlist entry {item!r}")
            found.add((host, port))
            if slash:
                paths.setdefault((host, port), set()).add("/" + path.strip("/"))
        return cls(frozenset(found), tuple(sorted((k, tuple(sorted(v)))
                                                  for k, v in paths.items())))

    def allows(self, host: str, port: int, path: str | None = None) -> bool:
        """With path None (CONNECT, SNI) a path-restricted host is refused."""
        key = (normal_host(host), port)
        if key not in self.entries:
            return False
        prefixes = dict(self.paths).get(key)
        if prefixes is None:
            return True
        if path is None:
            return False
        clean = "/" + path.split("?", 1)[0].lstrip("/")
        if "/../" in clean + "/" or "/./" in clean + "/" or "%" in clean:
            return False
        return any(clean == p or clean.startswith(p.rstrip("/") + "/") for p in prefixes)

    def names(self) -> frozenset[str]:
        """Host names (not IP literals) that DNS should answer."""
        return frozenset(h for h, _ in self.entries if not _is_ip(h))

    def to_list(self) -> list[str]:
        paths = dict(self.paths)
        return sorted(f"{h}:{p}{path}" for h, p in self.entries
                      for path in paths.get((h, p), ("",)))


def normal_host(host: str) -> str:
    return host.strip().strip("[]").lower().rstrip(".")


def split_host_port(text: str, default_port: int) -> tuple[str, int]:
    """'host', 'host:port' or '[v6]:port' to (host, port). A bad port is 0,
    which no allowlist entry has."""
    text = text.strip()
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else ""
    elif text.count(":") == 1:
        host, _, port = text.partition(":")
    else:
        host, port = text, ""
    if not port:
        return normal_host(host), default_port
    return normal_host(host), int(port) if port.isdigit() and 0 < int(port) < 65536 else 0


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


@dataclass(frozen=True)
class Head:
    """An HTTP request head: the request line and headers, as received."""

    method: str
    target: str
    version: str
    headers: list[tuple[str, str]]
    raw: bytes
    # Bytes read past the head (the start of a body).
    rest: bytes

    def header(self, name: str) -> str | None:
        name = name.lower()
        return next((v for k, v in self.headers if k.lower() == name), None)


def read_head(sock: socket.socket, first: bytes = b"") -> Head:
    data = first
    while b"\r\n\r\n" not in data:
        if len(data) > MAX_HEAD:
            raise ValueError("request head too long")
        chunk = sock.recv(4096)
        if not chunk:
            raise ValueError("connection closed before the request head ended")
        data += chunk
    raw, _, rest = data.partition(b"\r\n\r\n")
    lines = raw.decode("latin-1").split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) != 3:
        raise ValueError("bad request line")
    headers = []
    for line in lines[1:]:
        name, colon, value = line.partition(":")
        if not colon:
            raise ValueError("bad header line")
        headers.append((name.strip(), value.strip()))
    return Head(parts[0].upper(), parts[1], parts[2], headers, raw, rest)


def origin_request(head: Head, path: str) -> bytes:
    """The head rewritten for the origin server: origin-form path, proxy
    and hop-by-hop headers dropped, one request per connection."""
    lines = [f"{head.method} {path} {head.version}"]
    lines += [f"{k}: {v}" for k, v in head.headers if k.lower() not in HOP_HEADERS]
    lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + head.rest


def parse_absolute(target: str) -> tuple[str, int, str]:
    """http://host[:port]/path to (host, port, path). Only http://."""
    if not target.lower().startswith("http://"):
        raise ValueError("only http:// URLs are proxied without CONNECT")
    rest = target[len("http://"):]
    authority, slash, path = rest.partition("/")
    authority = authority.rpartition("@")[2]
    host, port = split_host_port(authority, HTTP_PORT)
    return host, port, "/" + path if slash else "/"


def relay(a: socket.socket, b: socket.socket, idle: float = IDLE_TIMEOUT) -> None:
    """Copy bytes both ways until either side closes or goes idle."""
    sel = selectors.DefaultSelector()
    sel.register(a, selectors.EVENT_READ, b)
    sel.register(b, selectors.EVENT_READ, a)
    try:
        while True:
            ready = sel.select(idle)
            if not ready:
                return
            for key, _ in ready:
                try:
                    data = key.fileobj.recv(CHUNK)
                except OSError:
                    return
                if not data:
                    return
                key.data.sendall(data)
    except OSError:
        return
    finally:
        sel.close()


class Gateway:
    """The listeners and their shared allowlist and event sink."""

    def __init__(self, address: str, allowlist: Allowlist,
                 sink: Callable[[dict[str, Any]], None] = emit,
                 connect: Callable[[str, int], socket.socket] | None = None,
                 ports: dict[str, int] | None = None) -> None:
        self.address = address
        self.allowlist = allowlist
        self.sink = sink
        self.connect = connect or (lambda h, p: socket.create_connection((h, p), CONNECT_TIMEOUT))
        self.ports = {"proxy": PROXY_PORT, "http": HTTP_PORT, "tls": TLS_PORT, "dns": DNS_PORT,
                      **(ports or {})}
        self.servers: list[socketserver.BaseServer] = []

    # One decision, logged; returns the upstream socket or None.
    def open(self, host: str, port: int, via: str, client: str,
             path: str | None = None) -> socket.socket | None:
        event = {"event": "egress", "via": via, "host": host, "port": port, "client": client}
        if path is not None:
            event["path"] = path.split("?", 1)[0][:200]
        if not host or not self.allowlist.allows(host, port, path):
            self.sink({**event, "allowed": False, "reason": BLOCKED})
            return None
        try:
            upstream = self.connect(host, port)
        except OSError as e:
            self.sink({**event, "allowed": True, "error": f"upstream unreachable: {e}"})
            return None
        self.sink({**event, "allowed": True})
        return upstream

    def unreadable(self, via: str, client: str, why: str) -> None:
        self.sink({"event": "egress", "via": via, "host": UNREADABLE, "port": 0,
                   "client": client, "allowed": False, "reason": why})

    def handle_proxy(self, sock: socket.socket, client: str) -> None:
        try:
            head = read_head(sock)
        except (ValueError, OSError) as e:
            self.unreadable("connect", client, str(e))
            return
        if head.method == "CONNECT":
            host, port = split_host_port(head.target, TLS_PORT)
            upstream = self.open(host, port, "connect", client)
            if upstream is None:
                sock.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                return
            with upstream:
                sock.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                if head.rest:
                    upstream.sendall(head.rest)
                relay(sock, upstream)
            return
        try:
            host, port, path = parse_absolute(head.target)
        except ValueError as e:
            self.unreadable("http", client, str(e))
            sock.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return
        self._forward(sock, head, host, port, path, "http", client)

    def handle_http(self, sock: socket.socket, client: str) -> None:
        try:
            head = read_head(sock)
        except (ValueError, OSError) as e:
            self.unreadable("host", client, str(e))
            return
        host, port = split_host_port(head.header("host") or "", HTTP_PORT)
        path = head.target if head.target.startswith("/") else "/"
        self._forward(sock, head, host, port, path, "host", client)

    def _forward(self, sock, head: Head, host: str, port: int, path: str, via: str,
                 client: str) -> None:
        upstream = self.open(host, port, via, client, path)
        if upstream is None:
            sock.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n"
                         b"Connection: close\r\n\r\n")
            return
        with upstream:
            upstream.sendall(origin_request(head, path))
            relay(sock, upstream)

    def handle_tls(self, sock: socket.socket, client: str) -> None:
        try:
            first = _recv_exact(sock, 5)
            record = first + _recv_exact(sock, sni.record_length(first) - 5)
            host = sni.server_name(record)
        except (sni.SNIError, ValueError, OSError) as e:
            self.unreadable("sni", client, str(e))
            return
        upstream = self.open(host, TLS_PORT, "sni", client)
        if upstream is None:
            return
        with upstream:
            upstream.sendall(record)
            relay(sock, upstream)

    def handle_dns(self, packet: bytes, client: str) -> bytes | None:
        try:
            q = dns.parse_query(packet)
        except dns.DNSError as e:
            self.sink({"event": "dns", "name": UNREADABLE, "type": "", "client": client,
                       "allowed": False, "reason": str(e)})
            return dns.error_reply(packet)
        allowed = q.name in self.allowlist.names()
        self.sink({"event": "dns", "name": q.name, "type": q.type_name, "client": client,
                   "allowed": allowed})
        if allowed:
            return dns.answer(q, dns.NOERROR, self.address)
        return dns.answer(q, dns.NXDOMAIN)

    def start(self) -> None:
        """Start every listener in background threads."""
        gw = self

        def tcp(handler: Callable[[socket.socket, str], None]):
            class Handler(socketserver.BaseRequestHandler):
                def handle(self) -> None:
                    self.request.settimeout(HEAD_TIMEOUT)
                    try:
                        handler(self.request, self.client_address[0])
                    except OSError:
                        pass

            return Handler

        class UDP(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                packet, sock = self.request
                reply = gw.handle_dns(packet, self.client_address[0])
                if reply:
                    sock.sendto(reply, self.client_address)

        class TCPServer(socketserver.ThreadingTCPServer):
            daemon_threads = True
            allow_reuse_address = True

        class UDPServer(socketserver.ThreadingUDPServer):
            daemon_threads = True

        servers = {name: TCPServer((self.address, self.ports[name]), tcp(handler))
                   for name, handler in (("proxy", self.handle_proxy), ("http", self.handle_http),
                                         ("tls", self.handle_tls))}
        servers["dns"] = UDPServer((self.address, self.ports["dns"]), UDP)
        for name, server in servers.items():
            # A port of 0 in tests picks a free one: record what was bound.
            self.ports[name] = server.server_address[1]
            self.servers.append(server)
            threading.Thread(target=server.serve_forever, args=(0.1,), daemon=True).start()
        self.sink({"event": "ready", "address": self.address,
                   "allow": self.allowlist.to_list(), "ports": self.ports})

    def stop(self) -> None:
        for server in self.servers:
            server.shutdown()
            server.server_close()


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ValueError("connection closed early")
        data += chunk
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m lure.sandbox.gateway",
                                     description="Lure's sandbox egress proxy and DNS logger.")
    parser.add_argument("--address", required=True,
                        help="the gateway's address on the internal network")
    parser.add_argument("--allow", action="append", default=[], metavar="HOST[:PORT]",
                        help="an allowed host (port 443 when not given); repeatable")
    args = parser.parse_args(argv)
    gateway = Gateway(args.address, Allowlist.parse(args.allow))
    gateway.start()
    threading.Event().wait()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
