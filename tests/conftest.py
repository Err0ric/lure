import socket

import pytest


@pytest.fixture(autouse=True)
def no_network(request, monkeypatch):
    """Fail any test that opens a socket, except live smoke tests."""
    if request.node.get_closest_marker("ollama"):
        return

    def guard(*args, **kwargs):
        raise AssertionError("tests must never open a network connection")

    monkeypatch.setattr(socket, "socket", guard)
    monkeypatch.setattr(socket, "create_connection", guard)
