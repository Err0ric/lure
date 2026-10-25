"""lure serve safety: loopback only, Host checks against DNS rebinding,
security headers and no CORS, GET and HEAD only, hostile text escaped, no
SQL from requests, and a store connection that cannot install or load
extensions or read files."""

import socket
from pathlib import Path

import pytest

duckdb = pytest.importorskip("duckdb")
pytestmark = pytest.mark.loopback

from lure.serve import SECURITY_HEADERS, Dashboard, ServeError, make_server
from tests.test_serve import request, rows, site  # noqa: F401


@pytest.mark.parametrize("host", ["evil.example", "evil.example:{port}", "127.0.0.1",
                                  "127.0.0.1:1", "localhost.evil.example:{port}", False])
def test_a_request_for_another_host_is_refused(site, host):  # noqa: F811
    if isinstance(host, str):
        host = host.format(port=site["port"])
    status, headers, body = request(site, "/", host=host)
    assert status == 421
    assert "Runs" not in body
    assert headers["content-security-policy"] == SECURITY_HEADERS["Content-Security-Policy"]


def test_localhost_with_the_port_is_allowed(site):  # noqa: F811
    assert request(site, "/", host=f"localhost:{site['port']}")[0] == 200


@pytest.mark.parametrize("path", ["/", "/profiles", "/nothing"])
def test_security_headers_on_every_response_and_no_cors(site, path):  # noqa: F811
    _, headers, _ = request(site, path)
    for k, v in SECURITY_HEADERS.items():
        assert headers[k.lower()] == v
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["referrer-policy"] == "no-referrer"
    assert "script-src" not in headers["content-security-policy"]
    assert not [k for k in headers if k.startswith("access-control-")]


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def test_only_get_and_head_are_answered(site, method):  # noqa: F811
    status, headers, _ = request(site, "/", method=method)
    assert status == 405
    assert headers["x-content-type-options"] == "nosniff"


def test_hostile_text_in_a_run_is_escaped_never_rendered(site):  # noqa: F811
    run_id = rows(site, "SELECT id FROM runs WHERE folder LIKE '%hostile%' LIMIT 1")[0][0]
    status, _, body = request(site, f"/run/{run_id}")
    assert status == 200
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body
    assert "<script" not in body
    assert "<img" not in body
    assert 'src="https://evil.example' not in body


def test_no_sql_reaches_the_store_from_a_request(site):  # noqa: F811
    status, _, body = request(site, "/runs?verdict=Fail%27%20OR%201%3D1%20--&sql=DROP%20TABLE%20runs")
    assert status == 200 and "No runs match" in body
    assert rows(site, "SELECT count(*) FROM runs")[0][0] > 0


@pytest.mark.parametrize("sql", ["INSTALL httpfs", "LOAD httpfs", "FORCE INSTALL httpfs",
                                 "SET enable_external_access = true",
                                 "SELECT * FROM read_csv('/etc/hosts')"])
def test_the_dashboard_connection_cannot_install_load_or_read_files(site, sql):  # noqa: F811
    with pytest.raises(duckdb.Error):
        Dashboard(site["db"])._rows(sql)


def test_the_server_binds_loopback_only():
    with pytest.raises(ServeError, match="binds 127.0.0.1 only"):
        make_server(Dashboard(Path("x.duckdb")), port=0, host="0.0.0.0")


def test_the_loopback_guard_still_blocks_other_hosts():
    with pytest.raises(AssertionError, match="never open a network connection"):
        socket.create_connection(("192.0.2.1", 80), timeout=1)
