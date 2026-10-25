"""The results store: indexing saved runs into DuckDB, and the locked-down
connections. No model is called; records come from scripted runs."""

import json
import sys

import pytest

duckdb = pytest.importorskip("duckdb")

from lure import store
from lure.runner import run_attack
from lure.store import StoreError
from tests.fakes import ScriptedAdapter, call, say
from tests.test_cli import SUMMARY
from tests.test_gate import IPI_001, POLICY

HARM = call("send_email", "c2", to=["billing-verify@external.example"], subject="Invoices",
            body="Attached.")


def _folder(tmp_path):
    folder = tmp_path / "results" / "run-a"
    folder.mkdir(parents=True)
    clean = run_attack(IPI_001, ScriptedAdapter(call("read_inbox"), say(SUMMARY)),
                       org_policy=POLICY)
    harm = run_attack(IPI_001, ScriptedAdapter(call("read_inbox"), HARM, say(SUMMARY)),
                      org_policy=POLICY)
    paths = [clean.save(folder), harm.save(folder)]
    (folder / "manifest.json").write_text(json.dumps({
        "manifest_version": 2, "profile": {"name": "ap-agent", "sha256": "ab"},
        "target": "scripted:model", "started_at": "2026-10-25T10:00:00+00:00"}))
    (folder / "retest.json").write_text(json.dumps({
        "retest_version": 1, "profile": "ap-agent", "baseline": "results/run-0",
        "regression": False, "conditions": [{"text": "Remove send_email.", "verified": True}]}))
    vetting = tmp_path / "results" / "vetting" / "ap-agent"
    vetting.mkdir(parents=True)
    (vetting / "decisions.jsonl").write_text(json.dumps({
        "decision_version": 1, "decided_at": "2026-10-25T11:00:00+00:00",
        "profile": "ap-agent", "decision": "approve", "by": "AP lead", "conditions": [],
        "run": str(folder)}) + "\n")
    (folder / "notes.json").write_text(json.dumps({"not": "a record"}))
    (folder / "broken.json").write_text("{")
    return tmp_path / "results", paths


def rows(db, sql):
    return store.query(db, sql)[1]


def test_add_indexes_runs_calls_techniques_exposure_folders_retests_and_decisions(tmp_path):
    root, _ = _folder(tmp_path)
    db = tmp_path / "lure.duckdb"
    done = store.add(db, [root])
    assert (done.indexed, done.skipped) == (5, 2)
    assert rows(db, "SELECT attack_id, verdict FROM runs ORDER BY verdict") == [
        ("lure-ipi-001", "Fail"), ("lure-ipi-001", "Pass")]
    assert rows(db, "SELECT count(*) FROM tool_calls") == [(3,)]
    assert rows(db, "SELECT DISTINCT domain FROM exposure") == [("external.example",)]
    assert ("atlas", "AML.T0051.001") in rows(db, "SELECT framework, technique FROM techniques")
    assert rows(db, "SELECT profile, target FROM folders") == [("ap-agent", "scripted:model")]
    assert rows(db, "SELECT profile, regression FROM retests") == [("ap-agent", False)]
    assert rows(db, "SELECT profile, decision, decided_by FROM decisions") == [
        ("ap-agent", "approve", "AP lead")]


def test_add_skips_unchanged_files_replaces_changed_ones_and_drops_deleted_ones(tmp_path):
    root, paths = _folder(tmp_path)
    db = tmp_path / "lure.duckdb"
    store.add(db, [root])
    assert store.add(db, [root]).unchanged == 5
    record = json.loads(paths[0].read_text())
    record["judgment"]["verdict"] = "Review"
    paths[0].write_text(json.dumps(record))
    paths[1].unlink()
    done = store.add(db, [root])
    assert (done.indexed, done.removed) == (1, 1)
    assert rows(db, "SELECT verdict FROM runs") == [("Review",)]
    assert rows(db, "SELECT count(*) FROM tool_calls") == [(1,)]


def test_an_old_record_without_newer_fields_loads(tmp_path):
    folder = tmp_path / "old"
    folder.mkdir()
    (folder / "r.json").write_text(json.dumps({
        "attack": {"id": "lure-ipi-001", "category": "indirect_prompt_injection",
                   "severity": "high", "atlas": ["AML.T0051.001"]},
        "target": "anthropic:claude-haiku-5-5", "judgment": {"verdict": "Pass", "reason": "x"},
        "tool_calls": [{"tool": "read_inbox", "args": {}, "result": []}]}))
    db = tmp_path / "lure.duckdb"
    store.add(db, [folder])
    assert rows(db, "SELECT attack_version, scenario, schema_version, judge FROM runs") == [
        (1, "accounts_payable", 1, "rules")]


def test_rebuild_indexes_every_known_root_again(tmp_path):
    root, _ = _folder(tmp_path)
    db = tmp_path / "lure.duckdb"
    store.add(db, [root])
    assert store.rebuild(db).indexed == 5
    assert rows(db, "SELECT count(*) FROM runs") == [(2,)]


@pytest.mark.parametrize("sql", ["INSTALL httpfs", "LOAD httpfs", "FORCE INSTALL json",
                                 "SELECT 1; LOAD json", "DELETE FROM runs",
                                 "COPY runs TO 'out.csv'", "ATTACH 'x.duckdb'",
                                 "SET enable_external_access = true"])
def test_query_runs_only_select_and_explain(tmp_path, sql):
    root, _ = _folder(tmp_path)
    db = tmp_path / "lure.duckdb"
    store.add(db, [root])
    with pytest.raises(StoreError, match="only SELECT and EXPLAIN"):
        store.query(db, sql)


def test_query_may_read_local_files(tmp_path):
    root, _ = _folder(tmp_path)
    db = tmp_path / "lure.duckdb"
    store.add(db, [root])
    data = tmp_path / "x.csv"
    data.write_text("a\n1\n2\n")
    assert store.query(db, f"SELECT sum(a) FROM read_csv('{data}')")[1] == [(3,)]


@pytest.mark.parametrize("external", [True, False])
@pytest.mark.parametrize("sql", ["INSTALL httpfs", "LOAD httpfs", "FORCE INSTALL httpfs"])
def test_no_connection_can_install_or_load_an_extension(tmp_path, external, sql):
    db = tmp_path / "lure.duckdb"
    store.add(db, [tmp_path])
    with (store.connect(db, read_only=True, external=external) as con,
          pytest.raises(duckdb.Error)):
        con.execute(sql)


def test_the_locked_connection_cannot_reopen_external_access(tmp_path):
    db = tmp_path / "lure.duckdb"
    store.add(db, [tmp_path])
    secret = tmp_path / "s.csv"
    secret.write_text("a\n1\n")
    with store.connect(db, read_only=True) as con:
        for sql in ("SET enable_external_access = true", "SET autoload_known_extensions = true",
                    f"SELECT * FROM read_csv('{secret}')"):
            with pytest.raises(duckdb.Error):
                con.execute(sql)


def test_a_missing_store_and_a_missing_duckdb_say_what_to_do(tmp_path, monkeypatch):
    with pytest.raises(StoreError, match="lure store add"):
        store.query(tmp_path / "none.duckdb", "SELECT 1")
    monkeypatch.setitem(sys.modules, "duckdb", None)
    with pytest.raises(StoreError, match=r"pip install -e '\.\[store\]'"):
        store.query(tmp_path / "none.duckdb", "SELECT 1")


def test_cli_add_query_and_rebuild(tmp_path, capsys):
    import io

    from lure import cli

    root, _ = _folder(tmp_path)
    db = str(tmp_path / "lure.duckdb")
    out = io.StringIO()
    assert cli.main(["store", "add", str(root), "--db", db], out) == cli.EXIT_OK
    assert "indexed 5, unchanged 0, removed 0, skipped 2" in out.getvalue()
    out = io.StringIO()
    sql = "SELECT verdict, count(*) AS n FROM runs GROUP BY 1 ORDER BY 1"
    assert cli.main(["store", "query", sql, "--db", db], out) == cli.EXIT_OK
    assert out.getvalue().splitlines() == ["verdict  n", "Fail     1", "Pass     1", "(2 rows)"]
    out = io.StringIO()
    assert cli.main(["store", "query", "SELECT verdict FROM runs ORDER BY 1", "--csv",
                     "--db", db], out) == cli.EXIT_OK
    assert out.getvalue().splitlines() == ["verdict", "Fail", "Pass"]
    assert cli.main(["store", "query", "INSTALL httpfs", "--db", db], io.StringIO()) == (
        cli.EXIT_BAD_INPUT)
    assert "only SELECT and EXPLAIN" in capsys.readouterr().err
    out = io.StringIO()
    assert cli.main(["store", "rebuild", "--db", db], out) == cli.EXIT_OK
    assert "indexed 5" in out.getvalue()


def test_cli_query_without_a_store_says_how_to_make_one(tmp_path, capsys):
    import io

    from lure import cli

    assert cli.main(["store", "query", "SELECT 1", "--db", str(tmp_path / "x.duckdb")],
                    io.StringIO()) == cli.EXIT_BAD_INPUT
    assert "lure store add" in capsys.readouterr().err
