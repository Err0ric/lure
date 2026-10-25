"""The sandbox gateway without Docker: DNS and SNI parsing, the allowlist,
and the listeners' decisions over loopback with a stand-in upstream."""

import socket
import struct
import threading

import pytest

from lure.sandbox import dns, sni
from lure.sandbox.gateway import (
    BLOCKED,
    Allowlist,
    Gateway,
    origin_request,
    parse_absolute,
    read_head,
    split_host_port,
)

# DNS

def test_dns_parses_a_query_and_answers_allowed_names_with_the_gateway():
    q = dns.parse_query(dns.build_query("API.Model.example", dns.QTYPE_A, qid=7))
    assert (q.id, q.name, q.type_name) == (7, "api.model.example", "A")
    reply = dns.answer(q, dns.NOERROR, "10.213.4.2")
    qid, flags, qd, an = struct.unpack("!HHHH", reply[:8])
    assert qid == 7 and flags & 0x8000 and flags & 0xF == dns.NOERROR and (qd, an) == (1, 1)
    assert reply.endswith(socket.inet_aton("10.213.4.2"))


def test_dns_nxdomain_and_empty_aaaa():
    q = dns.parse_query(dns.build_query("exfil.attacker.example"))
    reply = dns.answer(q, dns.NXDOMAIN)
    assert struct.unpack("!H", reply[2:4])[0] & 0xF == dns.NXDOMAIN
    assert struct.unpack("!H", reply[6:8])[0] == 0
    aaaa = dns.parse_query(dns.build_query("api.model.example", dns.QTYPE_AAAA))
    assert struct.unpack("!H", dns.answer(aaaa, dns.NOERROR, "10.0.0.2")[6:8])[0] == 0


@pytest.mark.parametrize("packet", [b"", b"\x00" * 11, dns.build_query("a.example")[:-3],
                                    b"\x00\x01\x80\x00" + b"\x00" * 8,
                                    b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\xc0\x0c"])
def test_dns_rejects_bad_packets(packet):
    with pytest.raises(dns.DNSError):
        dns.parse_query(packet)


# SNI

def test_sni_reads_the_server_name():
    record = sni.client_hello("Api.Model.Example")
    assert sni.record_length(record[:5]) == len(record)
    assert sni.server_name(record) == "api.model.example"


@pytest.mark.parametrize("record", [b"\x17\x03\x01\x00\x05hello", b"\x16\x03",
                                    sni.client_hello("a.example")[:-4]])
def test_sni_rejects_what_is_not_a_client_hello(record):
    with pytest.raises(sni.SNIError):
        sni.server_name(record)


# Allowlist and request parsing

def test_allowlist_is_exact_host_and_port():
    allow = Allowlist.parse(["api.model.example", "ollama.example:11434"])
    assert allow.allows("API.model.example.", 443)
    assert not allow.allows("api.model.example", 80)
    assert not allow.allows("evil.api.model.example", 443)
    assert not allow.allows("model.example", 443)
    assert allow.allows("ollama.example", 11434)
    assert allow.names() == {"api.model.example", "ollama.example"}


def test_allowlist_never_answers_dns_for_ip_literals():
    assert Allowlist.parse(["192.0.2.10:443"]).names() == frozenset()


@pytest.mark.parametrize("text, port, expected", [
    ("a.example", 443, ("a.example", 443)),
    ("a.example:8080", 443, ("a.example", 8080)),
    ("[2001:db8::1]:443", 80, ("2001:db8::1", 443)),
    ("a.example:99999", 443, ("a.example", 0)),
    ("a.example:x", 443, ("a.example", 0)),
])
def test_split_host_port(text, port, expected):
    assert split_host_port(text, port) == expected


def test_absolute_form_and_origin_rewrite():
    assert parse_absolute("http://user@a.example:8080/v1/x?q=1") == ("a.example", 8080, "/v1/x?q=1")
    with pytest.raises(ValueError):
        parse_absolute("https://a.example/")

    class Fake:
        def __init__(self, data):
            self.data = [data]

        def recv(self, n):
            return self.data.pop(0) if self.data else b""

    head = read_head(Fake(b"POST http://a.example/v1 HTTP/1.1\r\nHost: a.example\r\n"
                          b"Proxy-Authorization: x\r\nConnection: keep-alive\r\n\r\nBODY"))
    out = origin_request(head, "/v1")
    assert out.startswith(b"POST /v1 HTTP/1.1\r\n")
    assert b"Proxy-Authorization" not in out and b"keep-alive" not in out
    assert out.endswith(b"Connection: close\r\n\r\nBODY")


# The gateway's listeners, over loopback, with a stand-in upstream.

class Upstream:
    """A stand-in for the allowed host: answers any bytes with UPSTREAM."""

    def __init__(self):
        self.seen = []

    def __call__(self, host, port):
        ours, theirs = socket.socketpair()
        self.seen.append((host, port))

        def serve():
            data = theirs.recv(65536)
            theirs.sendall(b"UPSTREAM " + data[:20])
            theirs.close()

        threading.Thread(target=serve, daemon=True).start()
        return ours


@pytest.fixture
def gateway():
    events = []
    upstream = Upstream()
    gw = Gateway("127.0.0.1", Allowlist.parse(["model.lure-test.example",
                                               "model.lure-test.example:8080"]),
                 sink=events.append, connect=upstream,
                 ports={"proxy": 0, "http": 0, "tls": 0, "dns": 0})
    gw.start()
    yield gw, events, upstream
    gw.stop()


def _talk(port, data):
    s = socket.create_connection(("127.0.0.1", port), 5)
    s.sendall(data)
    chunks = []
    while True:
        try:
            chunk = s.recv(65536)
        except ConnectionResetError:
            # The gateway hung up without reading what was left: refused.
            break
        if not chunk:
            break
        chunks.append(chunk)
    s.close()
    return b"".join(chunks)


@pytest.mark.loopback
def test_connect_allowed_and_blocked(gateway):
    gw, events, upstream = gateway
    ok = _talk(gw.ports["proxy"], b"CONNECT model.lure-test.example:443 HTTP/1.1\r\n\r\nHELLO")
    assert ok.startswith(b"HTTP/1.1 200") and b"UPSTREAM HELLO" in ok
    no = _talk(gw.ports["proxy"], b"CONNECT api.model-relay.example:443 HTTP/1.1\r\n\r\n")
    assert no.startswith(b"HTTP/1.1 403")
    ip = _talk(gw.ports["proxy"], b"CONNECT 192.0.2.10:443 HTTP/1.1\r\n\r\n")
    assert ip.startswith(b"HTTP/1.1 403")
    assert upstream.seen == [("model.lure-test.example", 443)]
    egress = [e for e in events if e["event"] == "egress"]
    assert [(e["host"], e["allowed"]) for e in egress] == [
        ("model.lure-test.example", True), ("api.model-relay.example", False),
        ("192.0.2.10", False)]
    assert egress[1]["reason"] == BLOCKED and egress[1]["via"] == "connect"


@pytest.mark.loopback
def test_plain_http_proxy_and_host_header(gateway):
    gw, events, _upstream = gateway
    ok = _talk(gw.ports["proxy"], b"GET http://model.lure-test.example:8080/v1 HTTP/1.1\r\n"
                                  b"Host: model.lure-test.example:8080\r\n\r\n")
    assert ok.startswith(b"UPSTREAM GET /v1 HTTP/1.1")
    no = _talk(gw.ports["http"], b"GET / HTTP/1.1\r\nHost: exfil.attacker.example\r\n\r\n")
    assert no.startswith(b"HTTP/1.1 403")
    bad = _talk(gw.ports["proxy"], b"GET https://x.example/ HTTP/1.1\r\n\r\n")
    assert bad.startswith(b"HTTP/1.1 400")
    vias = [(e["via"], e["host"], e["allowed"]) for e in events if e["event"] == "egress"]
    assert vias == [("http", "model.lure-test.example", True),
                    ("host", "exfil.attacker.example", False),
                    ("http", "(unreadable)", False)]


@pytest.mark.loopback
def test_sni_passthrough(gateway):
    gw, events, _upstream = gateway
    hello = sni.client_hello("model.lure-test.example")
    assert _talk(gw.ports["tls"], hello) == b"UPSTREAM " + hello[:20]
    assert _talk(gw.ports["tls"], sni.client_hello("blocked.attacker.example")) == b""
    assert _talk(gw.ports["tls"], b"GET / HTTP/1.1\r\n\r\n") == b""
    vias = [(e["via"], e["host"], e["allowed"]) for e in events if e["event"] == "egress"]
    assert vias == [("sni", "model.lure-test.example", True),
                    ("sni", "blocked.attacker.example", False),
                    ("sni", "(unreadable)", False)]


@pytest.mark.loopback
def test_dns_listener_logs_every_name(gateway):
    gw, events, _ = gateway
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    for name in ("model.lure-test.example", "exfil.attacker.example"):
        s.sendto(dns.build_query(name), ("127.0.0.1", gw.ports["dns"]))
        s.recvfrom(512)
    s.close()
    assert [(e["name"], e["allowed"]) for e in events if e["event"] == "dns"] == [
        ("model.lure-test.example", True), ("exfil.attacker.example", False)]


def test_a_path_restricted_entry():
    allow = Allowlist.parse(["ollama.example:11434/api/chat"])
    assert allow.allows("ollama.example", 11434, "/api/chat")
    assert allow.allows("ollama.example", 11434, "/api/chat?x=1")
    assert not allow.allows("ollama.example", 11434, "/api/delete")
    assert not allow.allows("ollama.example", 11434, "/api/chatty")
    assert not allow.allows("ollama.example", 11434, "/api/chat/../delete")
    assert not allow.allows("ollama.example", 11434, "/api/%63hat")
    # A tunnel would hide the path: CONNECT and SNI are refused.
    assert not allow.allows("ollama.example", 11434)
    assert allow.to_list() == ["ollama.example:11434/api/chat"]
    with pytest.raises(ValueError):
        Allowlist.parse(["ollama.example:0/api/chat"])


@pytest.mark.loopback
def test_a_local_model_host_is_held_to_its_chat_endpoint():
    events = []
    upstream = Upstream()
    gw = Gateway("127.0.0.1", Allowlist.parse(["ollama.example:11434/api/chat"]),
                 sink=events.append, connect=upstream,
                 ports={"proxy": 0, "http": 0, "tls": 0, "dns": 0})
    gw.start()
    try:
        chat = _talk(gw.ports["proxy"], b"POST http://ollama.example:11434/api/chat HTTP/1.1\r\n"
                                        b"Host: ollama.example:11434\r\n\r\n")
        delete = _talk(gw.ports["proxy"], b"DELETE http://ollama.example:11434/api/delete "
                                          b"HTTP/1.1\r\nHost: ollama.example:11434\r\n\r\n")
        tunnel = _talk(gw.ports["proxy"], b"CONNECT ollama.example:11434 HTTP/1.1\r\n\r\n")
    finally:
        gw.stop()
    assert chat.startswith(b"UPSTREAM POST /api/chat")
    assert delete.startswith(b"HTTP/1.1 403") and tunnel.startswith(b"HTTP/1.1 403")
    assert upstream.seen == [("ollama.example", 11434)]
    blocked = [e for e in events if e["event"] == "egress" and not e["allowed"]]
    assert [(e["via"], e.get("path")) for e in blocked] == [("http", "/api/delete"),
                                                            ("connect", None)]
