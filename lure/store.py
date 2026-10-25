"""Results store: an index of saved runs in a local DuckDB file.

The JSON result files stay the source of truth. The store reads result
folders (run records, run manifests, retest.json and decision logs) into one
database so runs can be queried across folders, targets and dates; it can be
rebuilt from the files at any time and never replaces them.

DuckDB is an optional extra: pip install -e '.[store]'.

Safety: every connection turns off extension autoinstall and autoload and
community or unsigned extensions. Indexing and lure serve also turn off
external access (no file or network reads from SQL) and lock the
configuration. lure store query may read local files, but only runs SELECT
or EXPLAIN statements, on a read-only connection whose extension directory
and repository are an empty local folder, so INSTALL and LOAD have nothing
to install or load.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from lure.rescore import MANIFEST, RETEST

DEFAULT_DB = "results/lure.duckdb"
SCHEMA_VERSION = 1
DECISIONS = "decisions.jsonl"
# Statements lure store query runs: reads only.
QUERY_STATEMENTS = ("SELECT", "EXPLAIN")
SAFE_CONFIG = {
    "autoinstall_known_extensions": False,
    "autoload_known_extensions": False,
    "allow_community_extensions": False,
    "allow_unsigned_extensions": False,
}

TABLES = """
CREATE TABLE IF NOT EXISTS meta (key VARCHAR PRIMARY KEY, value VARCHAR);
CREATE TABLE IF NOT EXISTS sources (
    path VARCHAR PRIMARY KEY, sha256 VARCHAR, kind VARCHAR, folder VARCHAR,
    indexed_at TIMESTAMP);
CREATE SEQUENCE IF NOT EXISTS run_ids;
CREATE TABLE IF NOT EXISTS runs (
    id BIGINT PRIMARY KEY, path VARCHAR UNIQUE, folder VARCHAR,
    attack_id VARCHAR, attack_version INTEGER, attack_name VARCHAR, category VARCHAR,
    scenario VARCHAR, severity VARCHAR, variant_id VARCHAR, variant_kind VARCHAR,
    target VARCHAR, judge VARCHAR, verdict VARCHAR, partial_kind VARCHAR, reason VARCHAR,
    detected BOOLEAN, llm_judged BOOLEAN, adaptive BOOLEAN, exposed BOOLEAN,
    profile VARCHAR, profile_sha256 VARCHAR, cost DOUBLE,
    input_tokens BIGINT, output_tokens BIGINT,
    started_at TIMESTAMP, finished_at TIMESTAMP,
    lure_version VARCHAR, schema_version INTEGER, stop VARCHAR, error VARCHAR,
    final_text VARCHAR, record JSON);
CREATE TABLE IF NOT EXISTS tool_calls (
    run_id BIGINT, idx INTEGER, tool VARCHAR, alias VARCHAR, gate VARCHAR,
    failed BOOLEAN, args JSON, result JSON);
CREATE TABLE IF NOT EXISTS techniques (run_id BIGINT, framework VARCHAR, technique VARCHAR);
CREATE TABLE IF NOT EXISTS exposure (run_id BIGINT, idx INTEGER, tool VARCHAR, domain VARCHAR);
CREATE TABLE IF NOT EXISTS folders (
    path VARCHAR PRIMARY KEY, profile VARCHAR, target VARCHAR, started_at TIMESTAMP,
    manifest JSON);
CREATE TABLE IF NOT EXISTS retests (
    folder VARCHAR PRIMARY KEY, profile VARCHAR, baseline VARCHAR, regression BOOLEAN,
    conditions JSON, record JSON);
CREATE TABLE IF NOT EXISTS decisions (
    source VARCHAR, line INTEGER, profile VARCHAR, decided_at TIMESTAMP,
    decision VARCHAR, decided_by VARCHAR, conditions JSON, run VARCHAR,
    profile_sha256 VARCHAR, record JSON);
"""


class StoreError(ValueError):
    """The store cannot be opened, or a query was refused."""


def _duckdb():
    try:
        import duckdb
    except ImportError:
        raise StoreError("the results store needs DuckDB: pip install -e '.[store]'") from None
    return duckdb


@contextmanager
def connect(db: str | Path, *, read_only: bool = False,
            external: bool = False) -> Iterator[Any]:
    """A connection with extensions locked down. external=False also turns
    off file and network access from SQL; either way the configuration is
    locked, so a statement cannot turn any of it back on."""
    duckdb = _duckdb()
    db = Path(db)
    if read_only and not db.is_file():
        raise StoreError(f"no results store at {db}; run lure store add <folders> first")
    if not read_only:
        db.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="lure-duckdb-ext-") as empty:
        config = {**SAFE_CONFIG, "extension_directory": empty,
                  "custom_extension_repository": os.path.join(empty, "none")}
        if not external:
            config["enable_external_access"] = False
        con = duckdb.connect(str(db), read_only=read_only, config=config)
        try:
            con.execute("SET lock_configuration = true")
            yield con
        finally:
            con.close()


@dataclass
class Added:
    """What one lure store add did."""

    indexed: int = 0
    unchanged: int = 0
    removed: int = 0
    skipped: int = 0


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _kind(path: Path) -> str | None:
    if path.name == MANIFEST:
        return "manifest"
    if path.name == RETEST:
        return "retest"
    if path.name == DECISIONS:
        return "decisions"
    if path.suffix == ".json":
        return "record"
    return None


def _files(roots: list[Path]) -> Iterator[tuple[Path, str]]:
    for root in roots:
        if root.is_file():
            kind = _kind(root)
            if kind:
                yield root.resolve(), kind
            continue
        if not root.is_dir():
            raise StoreError(f"results not found: {root}")
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames.sort()
            for name in sorted(filenames):
                path = Path(dirpath) / name
                kind = _kind(path)
                if kind:
                    yield path.resolve(), kind


def add(db: str | Path, roots: list[str | Path]) -> Added:
    """Index result folders and files. A file already indexed with the same
    contents is skipped; a changed one replaces its rows; an indexed file
    under these roots that is gone is removed."""
    roots = [Path(r) for r in roots]
    done = Added()
    with connect(db) as con:
        con.execute(TABLES)
        con.execute("INSERT OR REPLACE INTO meta VALUES ('schema_version', ?)",
                    [str(SCHEMA_VERSION)])
        known = dict(con.execute("SELECT path, sha256 FROM sources").fetchall())
        seen = set()
        for path, kind in _files(roots):
            key = str(path)
            seen.add(key)
            sha = _sha(path)
            if known.get(key) == sha:
                done.unchanged += 1
                continue
            try:
                data = _read(path, kind)
            except (json.JSONDecodeError, UnicodeDecodeError):
                done.skipped += 1
                continue
            if kind == "record" and not _is_record(data):
                done.skipped += 1
                continue
            _forget(con, key)
            _insert(con, path, kind, data)
            con.execute("INSERT OR REPLACE INTO sources VALUES (?, ?, ?, ?, ?)",
                        [key, sha, kind, str(path.parent),
                         datetime.now(UTC).replace(tzinfo=None)])
            done.indexed += 1
        under = [str(r.resolve()) for r in roots if r.is_dir()]
        for key in set(known) - seen:
            if any(key.startswith(u + os.sep) for u in under):
                _forget(con, key)
                done.removed += 1
        roots_known = set(json.loads(_meta(con, "roots") or "[]"))
        roots_known |= {str(r.resolve()) for r in roots}
        con.execute("INSERT OR REPLACE INTO meta VALUES ('roots', ?)",
                    [json.dumps(sorted(roots_known))])
    return done


def rebuild(db: str | Path) -> Added:
    """Drop the store and index every root it knew again."""
    db = Path(db)
    if not db.is_file():
        raise StoreError(f"no results store at {db}")
    with connect(db, read_only=True) as con:
        roots = json.loads(_meta(con, "roots") or "[]")
    db.unlink()
    wal = db.with_name(db.name + ".wal")
    if wal.is_file():
        wal.unlink()
    return add(db, [r for r in roots if Path(r).exists()])


def query(db: str | Path, sql: str) -> tuple[list[str], list[tuple]]:
    """Run read-only SQL: SELECT or EXPLAIN only, on a read-only connection.
    Returns the column names and rows of the last statement."""
    duckdb = _duckdb()
    try:
        statements = duckdb.extract_statements(sql)
    except duckdb.Error as e:
        raise StoreError(f"query: {e}") from None
    if not statements:
        raise StoreError("query: no statement")
    for s in statements:
        kind = str(s.type).rsplit(".", 1)[-1]
        if kind not in QUERY_STATEMENTS:
            raise StoreError(f"query: only {' and '.join(QUERY_STATEMENTS)} statements run "
                             f"here, not {kind}")
    with connect(db, read_only=True, external=True) as con:
        try:
            cursor = None
            for s in statements:
                cursor = con.execute(s)
            columns = [d[0] for d in cursor.description or []]
            return columns, cursor.fetchall()
        except duckdb.Error as e:
            raise StoreError(f"query: {e}") from None


def _meta(con, key: str) -> str | None:
    row = con.execute("SELECT value FROM meta WHERE key = ?", [key]).fetchone()
    return row[0] if row else None


def _read(path: Path, kind: str) -> Any:
    text = path.read_text(encoding="utf-8")
    if kind == "decisions":
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    return json.loads(text)


def _is_record(data: Any) -> bool:
    return isinstance(data, dict) and isinstance(data.get("attack"), dict) and isinstance(
        data.get("judgment"), dict) and "target" in data


def _forget(con, key: str) -> None:
    ids = [r[0] for r in con.execute("SELECT id FROM runs WHERE path = ?", [key]).fetchall()]
    for table in ("tool_calls", "techniques", "exposure"):
        for run_id in ids:
            con.execute(f"DELETE FROM {table} WHERE run_id = ?", [run_id])
    con.execute("DELETE FROM runs WHERE path = ?", [key])
    folder = str(Path(key).parent)
    if Path(key).name == MANIFEST:
        con.execute("DELETE FROM folders WHERE path = ?", [folder])
    if Path(key).name == RETEST:
        con.execute("DELETE FROM retests WHERE folder = ?", [folder])
    con.execute("DELETE FROM decisions WHERE source = ?", [key])
    con.execute("DELETE FROM sources WHERE path = ?", [key])


def _time(value: Any) -> datetime | None:
    """A saved time as naive UTC: the store keeps every time in UTC, and
    plain TIMESTAMP columns need no timezone package to read back."""
    if not isinstance(value, str):
        return None
    try:
        t = datetime.fromisoformat(value)
    except ValueError:
        return None
    return t.astimezone(UTC).replace(tzinfo=None) if t.tzinfo else t


def _profile_name(profile: Any) -> str | None:
    if isinstance(profile, dict):
        return profile.get("name")
    return profile if isinstance(profile, str) else None


def _insert(con, path: Path, kind: str, data: Any) -> None:
    if kind == "record":
        _insert_run(con, path, data)
    elif kind == "manifest" and isinstance(data, dict):
        con.execute("INSERT OR REPLACE INTO folders VALUES (?, ?, ?, ?, ?)",
                    [str(path.parent), _profile_name(data.get("profile")), data.get("target"),
                     _time(data.get("started_at")), json.dumps(data)])
    elif kind == "retest" and isinstance(data, dict):
        con.execute("INSERT OR REPLACE INTO retests VALUES (?, ?, ?, ?, ?, ?)",
                    [str(path.parent), _profile_name(data.get("profile")),
                     data.get("baseline"), bool(data.get("regression")),
                     json.dumps(data.get("conditions", [])), json.dumps(data)])
    elif kind == "decisions" and isinstance(data, list):
        for i, d in enumerate(data, 1):
            if not isinstance(d, dict):
                continue
            con.execute("INSERT INTO decisions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        [str(path), i, d.get("profile") or path.parent.name,
                         _time(d.get("decided_at")), d.get("decision"), d.get("by"),
                         json.dumps(d.get("conditions", [])), d.get("run"),
                         d.get("profile_sha256"), json.dumps(d)])


def _insert_run(con, path: Path, r: dict[str, Any]) -> None:
    attack, judgment = r["attack"], r["judgment"]
    variant = r.get("variant") or {}
    profile = r.get("profile") or {}
    usage = r.get("usage") or {}
    exposure = r.get("exposure") or {}
    calls = r.get("tool_calls") or []
    cost = (r.get("cost") or {}).get("total")
    judge = r.get("judge") or ((judgment.get("llm_judge") or {}).get("model") or "rules")
    run_id = con.execute("SELECT nextval('run_ids')").fetchone()[0]
    con.execute(
        "INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,"
        " ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [run_id, str(path), str(path.parent), attack.get("id"), attack.get("version", 1),
         attack.get("name"), attack.get("category"),
         attack.get("scenario", "accounts_payable"), attack.get("severity"),
         variant.get("id"), variant.get("kind"), r.get("target"), judge,
         judgment.get("verdict"), judgment.get("partial_kind"), judgment.get("reason"),
         judgment.get("verdict") == "Pass" and judgment.get("reason") == "detected",
         bool(judgment.get("llm_judged")), bool(r.get("adaptive")),
         bool(exposure.get("calls") or exposure.get("rendered")),
         _profile_name(profile), profile.get("sha256") if isinstance(profile, dict) else None,
         cost, usage.get("input_tokens"), usage.get("output_tokens"),
         _time(r.get("started_at")), _time(r.get("finished_at")), r.get("lure_version"),
         r.get("schema_version", 1), r.get("stop"),
         json.dumps(r["error"]) if isinstance(r.get("error"), dict) else r.get("error"),
         r.get("final_text"), json.dumps(r)])
    for i, c in enumerate(calls):
        result = c.get("result")
        con.execute("INSERT INTO tool_calls VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    [run_id, i, c.get("tool"), c.get("alias"), c.get("gate"),
                     isinstance(result, dict) and "error" in result,
                     json.dumps(c.get("args")), json.dumps(result)])
    for framework, ids in (("atlas", attack.get("atlas") or []),
                           ("attack", attack.get("attack") or [])):
        for t in ids:
            con.execute("INSERT INTO techniques VALUES (?, ?, ?)", [run_id, framework, t])
    for axis, codes in (attack.get("arcanum") or {}).items():
        for code in codes:
            con.execute("INSERT INTO techniques VALUES (?, ?, ?)",
                        [run_id, f"arcanum:{axis}", code])
    for e in exposure.get("calls") or []:
        for domain in e.get("outside") or []:
            con.execute("INSERT INTO exposure VALUES (?, ?, ?, ?)",
                        [run_id, e.get("index"), e.get("tool"), domain])
