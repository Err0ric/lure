import socket

import pytest

LOOPBACK = ("127.0.0.1", "localhost")


@pytest.fixture(autouse=True)
def no_network(request, monkeypatch):
    """Fail any test that opens a socket or resolves a name, except live
    smoke tests. A loopback test may reach 127.0.0.1 and nothing else."""
    if request.node.get_closest_marker("ollama"):
        return

    def guard(*args, **kwargs):
        raise AssertionError("tests must never open a network connection")

    if request.node.get_closest_marker("loopback"):
        connect, getaddrinfo = socket.socket.connect, socket.getaddrinfo

        def local_connect(self, address):
            if not (isinstance(address, tuple) and address[0] in LOOPBACK):
                guard()
            return connect(self, address)

        def local_getaddrinfo(host, *args, **kwargs):
            if host not in LOOPBACK:
                guard()
            return getaddrinfo(host, *args, **kwargs)

        monkeypatch.setattr(socket.socket, "connect", local_connect)
        monkeypatch.setattr(socket.socket, "connect_ex", guard)
        monkeypatch.setattr(socket, "getaddrinfo", local_getaddrinfo)
        return

    # Patch the class methods first: code that captured socket.socket at
    # import time still holds the original class.
    monkeypatch.setattr(socket.socket, "connect", guard)
    monkeypatch.setattr(socket.socket, "connect_ex", guard)
    monkeypatch.setattr(socket, "socket", guard)
    monkeypatch.setattr(socket, "create_connection", guard)
    monkeypatch.setattr(socket, "getaddrinfo", guard)
