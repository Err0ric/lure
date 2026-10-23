import socket

import pytest


@pytest.fixture(autouse=True)
def no_network(request, monkeypatch):
    """Fail any test that opens a socket or resolves a name, except live
    smoke tests."""
    if request.node.get_closest_marker("ollama"):
        return

    def guard(*args, **kwargs):
        raise AssertionError("tests must never open a network connection")

    # Patch the class methods first: code that captured socket.socket at
    # import time still holds the original class.
    monkeypatch.setattr(socket.socket, "connect", guard)
    monkeypatch.setattr(socket.socket, "connect_ex", guard)
    monkeypatch.setattr(socket, "socket", guard)
    monkeypatch.setattr(socket, "create_connection", guard)
    monkeypatch.setattr(socket, "getaddrinfo", guard)
