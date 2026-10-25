"""Read the server name (SNI) from a TLS ClientHello, without decrypting.

The gateway's port 443 listener reads the first TLS record a client sends,
takes the host name from its server_name extension, and decides from that
alone. The bytes are then passed through unchanged: Lure never terminates
TLS, never sees the request inside, and holds no certificate.
"""

from __future__ import annotations

import struct

HANDSHAKE = 22
CLIENT_HELLO = 1
SERVER_NAME = 0
HOST_NAME = 0
# A ClientHello fits in one record; anything bigger is refused.
MAX_RECORD = 16384


class SNIError(ValueError):
    """Not a ClientHello with a host name."""


def record_length(head: bytes) -> int:
    """The full length of the TLS record whose 5-byte header is `head`."""
    if len(head) < 5:
        raise SNIError("short record header")
    if head[0] != HANDSHAKE:
        raise SNIError("not a TLS handshake")
    (n,) = struct.unpack("!H", head[3:5])
    if n > MAX_RECORD:
        raise SNIError("record too long")
    return 5 + n


def server_name(record: bytes) -> str:
    """The host name in a ClientHello record, lowercased."""
    if len(record) < record_length(record):
        raise SNIError("truncated record")
    body = record[5:record_length(record)]
    if not body or body[0] != CLIENT_HELLO:
        raise SNIError("not a ClientHello")
    i = 4 + 2 + 32  # handshake header, version, random
    i = _skip(body, i, 1)  # session id
    i = _skip(body, i, 2)  # cipher suites
    i = _skip(body, i, 1)  # compression methods
    if i + 2 > len(body):
        raise SNIError("no extensions")
    (ext_total,) = struct.unpack("!H", body[i:i + 2])
    i += 2
    end = min(len(body), i + ext_total)
    while i + 4 <= end:
        ext_type, ext_len = struct.unpack("!HH", body[i:i + 4])
        data = body[i + 4:i + 4 + ext_len]
        i += 4 + ext_len
        if ext_type != SERVER_NAME:
            continue
        j = 2  # server name list length
        while j + 3 <= len(data):
            kind, n = data[j], struct.unpack("!H", data[j + 1:j + 3])[0]
            name = data[j + 3:j + 3 + n]
            if kind == HOST_NAME and name:
                try:
                    return name.decode("ascii").lower().rstrip(".")
                except UnicodeDecodeError as e:
                    raise SNIError("host name is not ASCII") from e
            j += 3 + n
    raise SNIError("no server name")


def _skip(body: bytes, i: int, width: int) -> int:
    if i + width > len(body):
        raise SNIError("truncated ClientHello")
    n = int.from_bytes(body[i:i + width], "big")
    return i + width + n


def client_hello(host: str) -> bytes:
    """A minimal ClientHello naming `host`, for tests and the reference
    checks. Not a usable TLS handshake beyond its first record."""
    name = host.encode("ascii")
    sni = struct.pack("!HBH", len(name) + 3, HOST_NAME, len(name)) + name
    ext = struct.pack("!HH", SERVER_NAME, len(sni)) + sni
    hello = (b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00"
             + struct.pack("!H", len(ext)) + ext)
    handshake = bytes([CLIENT_HELLO]) + len(hello).to_bytes(3, "big") + hello
    return bytes([HANDSHAKE]) + b"\x03\x01" + struct.pack("!H", len(handshake)) + handshake
