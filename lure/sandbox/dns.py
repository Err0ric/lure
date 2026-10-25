"""DNS packets for the sandbox's logging DNS responder.

Only what the responder needs: read the question of a query, and build an
answer. An allowed name gets one A record pointing at the gateway (so a
client that ignores the proxy settings still reaches the gateway's SNI and
Host listeners, never the real host); every other name gets NXDOMAIN. The
gateway logs every question either way. Nothing here resolves a real name.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass

QTYPE_A = 1
QTYPE_AAAA = 28
QTYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
               28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY"}
CLASS_IN = 1
NOERROR = 0
FORMERR = 1
NXDOMAIN = 3
# Names longer than DNS allows are malformed.
MAX_NAME = 253
TTL = 5


class DNSError(ValueError):
    """The packet is not a DNS query this responder can read."""


@dataclass(frozen=True)
class Question:
    id: int
    flags: int
    name: str
    qtype: int
    qclass: int
    # The question section as received, echoed in the answer.
    raw: bytes

    @property
    def type_name(self) -> str:
        return QTYPE_NAMES.get(self.qtype, str(self.qtype))


def parse_query(packet: bytes) -> Question:
    """The first question of a query. Compression pointers are refused: a
    client's question never needs them."""
    if len(packet) < 12:
        raise DNSError("short packet")
    qid, flags, qdcount = struct.unpack("!HHH", packet[:6])
    if flags & 0x8000:
        raise DNSError("not a query")
    if qdcount < 1:
        raise DNSError("no question")
    labels, i = [], 12
    while True:
        if i >= len(packet):
            raise DNSError("truncated name")
        n = packet[i]
        if n == 0:
            i += 1
            break
        if n & 0xC0:
            raise DNSError("compressed name in a question")
        label = packet[i + 1:i + 1 + n]
        if len(label) != n:
            raise DNSError("truncated label")
        labels.append(label.decode("ascii", "replace"))
        i += 1 + n
    if i + 4 > len(packet):
        raise DNSError("truncated question")
    qtype, qclass = struct.unpack("!HH", packet[i:i + 4])
    name = ".".join(labels).lower()
    if len(name) > MAX_NAME:
        raise DNSError("name too long")
    return Question(qid, flags, name, qtype, qclass, packet[12:i + 4])


def answer(q: Question, rcode: int, address: str | None = None) -> bytes:
    """A response to the question: rcode, and one A record for `address`
    when it is given and the question asks for A (or ANY). An AAAA question
    for an allowed name gets an empty NOERROR answer, so clients fall back
    to IPv4."""
    rd = q.flags & 0x0100
    records = b""
    if rcode == NOERROR and address is not None and q.qtype in (QTYPE_A, 255):
        records = (b"\xc0\x0c" + struct.pack("!HHIH", QTYPE_A, CLASS_IN, TTL, 4)
                   + ipaddress.IPv4Address(address).packed)
    flags = 0x8000 | 0x0400 | rd | 0x0080 | rcode  # response, authoritative, RD, RA
    header = struct.pack("!HHHHHH", q.id, flags, 1, 1 if records else 0, 0, 0)
    return header + q.raw + records


def error_reply(packet: bytes) -> bytes | None:
    """FORMERR for a packet with a readable header, None otherwise."""
    if len(packet) < 12:
        return None
    qid, flags = struct.unpack("!HH", packet[:4])
    if flags & 0x8000:
        return None
    return struct.pack("!HHHHHH", qid, 0x8000 | FORMERR, 0, 0, 0, 0)


def build_query(name: str, qtype: int = QTYPE_A, qid: int = 0x1234) -> bytes:
    """A one-question query, for tests and the reference checks."""
    labels = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.split(".") if p)
    return (struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + labels + b"\x00"
            + struct.pack("!HH", qtype, CLASS_IN))
