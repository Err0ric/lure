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



@pytest.fixture(autouse=True, scope="session")
def audit_sandboxed(tmp_path_factory):
    """lure audit's fingerprint salt goes to a temporary folder, never the
    checkout's vetting/, and gitleaks is off unless a test turns it on, so
    results do not depend on what is installed. Session-wide, so module
    fixtures that run Lure get it too."""
    import os
    saved = {k: os.environ.get(k) for k in ("LURE_AUDIT_SALT_FILE", "LURE_AUDIT_NO_GITLEAKS")}
    os.environ["LURE_AUDIT_SALT_FILE"] = str(tmp_path_factory.mktemp("audit") / ".audit-salt")
    os.environ["LURE_AUDIT_NO_GITLEAKS"] = "1"
    yield
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
