"""Mock SIEM: describe_schema, run_query, list_alerts, update_alert and
disable_rule.

For the security operations scenario pack: log sources with their columns,
the events in them (each with its raw log line), the alert queue and the
detection rules, so an agent can search logs, triage alerts, or turn a rule
off. A raw log line is written by whoever caused the event, so it is where
an attacker plants text for an AI analyst to read.

run_query is a small stand-in for a query engine, not SQL: a SELECT returns
the events of every source the query names, filtered by `column = 'value'`
and `column LIKE '%value%'` conditions joined by AND, and cut by LIMIT. A
statement that changes data (DELETE, DROP, TRUNCATE, UPDATE, INSERT, ALTER)
is accepted and reported as done, so the log shows whether the agent tried;
DELETE, DROP and TRUNCATE remove the events from this run's copy.

Safety: everything comes from a JSON fixture and lives in memory for the
run. No database, query engine or SIEM is touched; a change edits only that
copy. Every call is recorded in the shared ToolCallLog, with its return
value, for the Judge.
"""

from __future__ import annotations

import copy
import re
from typing import Any

from lure.tools.args import ToolArgumentError, ToolError, as_text
from lure.tools.call_log import ToolCallLog
from lure.tools.mock_email import FixtureError

SOURCE_KEYS = {"name", "description", "columns"}
SOURCE_OPTIONAL = {"restricted"}
ALERT_KEYS = {"id", "rule", "title", "severity", "status", "host", "events"}
RULE_KEYS = {"id", "name", "enabled"}
# Statuses an agent may set on an alert.
ALERT_STATUSES = ("open", "acknowledged", "escalated", "closed_benign", "closed_true_positive")
WRITE_VERBS = ("delete", "drop", "truncate", "update", "insert", "alter")
NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")
CONDITION_RE = re.compile(r"\b([a-z_][a-z0-9_]*)\s*(=|like)\s*'([^']*)'", re.IGNORECASE)
LIMIT_RE = re.compile(r"\blimit\s+(\d+)\b", re.IGNORECASE)
# The WHERE clause, up to ORDER BY, GROUP BY, LIMIT or the end.
WHERE_RE = re.compile(r"\bwhere\b(.*?)(?=\border\s+by\b|\bgroup\s+by\b|\blimit\b|$)",
                      re.IGNORECASE | re.DOTALL)
# Rows a query returns at most, as a real engine caps a preview.
MAX_ROWS = 200


def check_siem(siem: Any) -> None:
    """A siem fixture is {sources, events} and optionally alerts and rules.
    sources: name, description, columns (names) and optional restricted
    (true: the source is limited to some teams). events: id, source, and a
    string for every column of its source. alerts: id, rule, title, severity,
    status, host and events (event ids). rules: id, name, enabled."""
    if not isinstance(siem, dict) or not (
            {"sources", "events"} <= set(siem) <= {"sources", "events", "alerts", "rules"}):
        raise FixtureError("siem fixture must be an object with sources and events "
                           "(and optionally alerts and rules)")
    sources = siem["sources"]
    if not isinstance(sources, list) or not sources:
        raise FixtureError("siem sources must be a non-empty list")
    columns: dict[str, list[str]] = {}
    for i, s in enumerate(sources):
        where = f"siem sources[{i}]"
        if not isinstance(s, dict) or not SOURCE_KEYS <= set(s) <= SOURCE_KEYS | SOURCE_OPTIONAL:
            raise FixtureError(f"{where} must have {', '.join(sorted(SOURCE_KEYS))} "
                               "and optionally restricted")
        if not isinstance(s["name"], str) or not NAME_RE.match(s["name"]):
            raise FixtureError(f"{where}.name must be a lowercase identifier")
        if s["name"] in columns:
            raise FixtureError(f"{where} duplicates source {s['name']!r}")
        if not isinstance(s["description"], str) or not s["description"]:
            raise FixtureError(f"{where}.description must be a non-empty string")
        cols = s["columns"]
        if (not isinstance(cols, list) or not cols
                or not all(isinstance(c, str) and NAME_RE.match(c) for c in cols)
                or len(set(cols)) != len(cols) or {"id", "source"} & set(cols)):
            raise FixtureError(f"{where}.columns must be unique lowercase names "
                               "(not id or source)")
        if not isinstance(s.get("restricted", False), bool):
            raise FixtureError(f"{where}.restricted must be true or false")
        columns[s["name"]] = cols
    events = siem["events"]
    if not isinstance(events, list):
        raise FixtureError("siem events must be a list")
    ids = set()
    for i, e in enumerate(events):
        where = f"siem events[{i}]"
        if not isinstance(e, dict) or e.get("source") not in columns:
            raise FixtureError(f"{where} must name a listed source")
        want = {"id", "source", *columns[e["source"]]}
        if set(e) != want:
            raise FixtureError(f"{where} must have id, source and the columns of "
                               f"{e['source']!r}: {', '.join(columns[e['source']])}")
        if not all(isinstance(v, str) for v in e.values()):
            raise FixtureError(f"{where} fields must be strings")
        if e["id"] in ids:
            raise FixtureError(f"{where} duplicates id {e['id']!r}")
        ids.add(e["id"])
    rule_ids = _check_rules(siem.get("rules", []))
    _check_alerts(siem.get("alerts", []), ids, rule_ids)


def _check_rules(rules: Any) -> set[str]:
    if not isinstance(rules, list):
        raise FixtureError("siem rules must be a list")
    seen: set[str] = set()
    for i, r in enumerate(rules):
        where = f"siem rules[{i}]"
        if not isinstance(r, dict) or set(r) != RULE_KEYS:
            raise FixtureError(f"{where} must have {', '.join(sorted(RULE_KEYS))}")
        if not (isinstance(r["id"], str) and r["id"] and isinstance(r["name"], str)
                and isinstance(r["enabled"], bool)):
            raise FixtureError(f"{where}: id and name are strings, enabled true or false")
        if r["id"] in seen:
            raise FixtureError(f"{where} duplicates id {r['id']!r}")
        seen.add(r["id"])
    return seen


def _check_alerts(alerts: Any, event_ids: set[str], rule_ids: set[str]) -> None:
    if not isinstance(alerts, list):
        raise FixtureError("siem alerts must be a list")
    seen = set()
    for i, a in enumerate(alerts):
        where = f"siem alerts[{i}]"
        if not isinstance(a, dict) or set(a) != ALERT_KEYS:
            raise FixtureError(f"{where} must have {', '.join(sorted(ALERT_KEYS))}")
        if not all(isinstance(a[k], str) for k in ALERT_KEYS - {"events"}):
            raise FixtureError(f"{where} fields must be strings, and events a list")
        if a["id"] in seen:
            raise FixtureError(f"{where} duplicates id {a['id']!r}")
        seen.add(a["id"])
        if a["status"] not in ALERT_STATUSES:
            raise FixtureError(f"{where}.status must be one of {', '.join(ALERT_STATUSES)}")
        if rule_ids and a["rule"] not in rule_ids:
            raise FixtureError(f"{where}.rule names unknown rule {a['rule']!r}")
        if not isinstance(a["events"], list) or not set(a["events"]) <= event_ids:
            raise FixtureError(f"{where}.events must list event ids from events")


def _like(pattern: str) -> re.Pattern[str]:
    """A SQL LIKE pattern (% any run, _ one character) as a whole-value regex."""
    parts = (".*" if c == "%" else "." if c == "_" else re.escape(c) for c in pattern)
    return re.compile("".join(parts) + r"\Z", re.IGNORECASE | re.DOTALL)


class MockSiem:
    """Log sources, events, alerts and rules exposing describe_schema,
    run_query, list_alerts, update_alert and disable_rule."""

    def __init__(self, siem: dict[str, Any], log: ToolCallLog) -> None:
        check_siem(siem)
        self._sources = copy.deepcopy(siem["sources"])
        self._events = copy.deepcopy(siem["events"])
        self._alerts = copy.deepcopy(siem.get("alerts", []))
        self._rules = copy.deepcopy(siem.get("rules", []))
        self.log = log

    def _source_names(self) -> list[str]:
        return [s["name"] for s in self._sources]

    def describe_schema(self, source: str | None = None) -> list[dict[str, Any]]:
        """Every log source with its columns, or one source."""
        args: dict[str, Any] = {}
        found = self._sources
        if source is not None:
            source = as_text("source", source).strip().lower()
            args["source"] = source
            found = [s for s in self._sources if s["name"] == source]
            if not found:
                raise ToolError(f"no source {source!r}; sources: "
                                f"{', '.join(self._source_names())}")
        result = [{"name": s["name"], "description": s["description"],
                   "columns": ["id", *s["columns"]],
                   "access": "restricted" if s.get("restricted") else "all analysts"}
                  for s in found]
        self.log.record("describe_schema", args, copy.deepcopy(result))
        return result

    def run_query(self, query: str) -> dict[str, Any]:
        """Run a query against the named log sources (see the module notes
        for what this mock understands)."""
        query = as_text("query", query).strip()
        if not query:
            raise ToolArgumentError("query must not be empty")
        lowered = query.lower()
        named = [n for n in self._source_names() if re.search(rf"\b{n}\b", lowered)]
        if not named:
            raise ToolError(f"the query names no source; sources: "
                            f"{', '.join(self._source_names())}")
        verb = lowered.split(None, 1)[0]
        if verb in WRITE_VERBS:
            result = self._write(verb, query, named)
        else:
            result = self._select(query, named)
        self.log.record("run_query", {"query": query}, copy.deepcopy(result))
        return result

    def _matching(self, query: str, named: list[str]) -> list[dict[str, Any]]:
        rows = [e for e in self._events if e["source"] in named]
        known = {"id", "source"} | {c for s in self._sources if s["name"] in named
                                    for c in s["columns"]}
        where = WHERE_RE.search(query)
        clause = where.group(1) if where else ""
        for column, op, value in CONDITION_RE.findall(clause):
            column = column.lower()
            if column not in known:
                raise ToolError(f"no column {column!r} in {', '.join(named)}")
            if op.lower() == "like":
                pattern = _like(value)
                rows = [r for r in rows if column in r and pattern.match(r[column])]
            else:
                rows = [r for r in rows if r.get(column, "").lower() == value.lower()]
        return rows

    def _select(self, query: str, named: list[str]) -> dict[str, Any]:
        rows = self._matching(query, named)
        limit = LIMIT_RE.search(query)
        cap = min(int(limit.group(1)), MAX_ROWS) if limit else MAX_ROWS
        return {"sources": named, "row_count": min(len(rows), cap),
                "rows": copy.deepcopy(rows[:cap])}

    def _write(self, verb: str, query: str, named: list[str]) -> dict[str, Any]:
        if verb in ("delete", "drop", "truncate"):
            gone = (self._matching(query, named) if verb == "delete"
                    else [e for e in self._events if e["source"] in named])
            ids = {e["id"] for e in gone}
            self._events = [e for e in self._events if e["id"] not in ids]
            affected = len(gone)
        elif verb == "update":
            affected = len(self._matching(query, named))
        else:
            affected = 1 if verb == "insert" else 0
        return {"status": "ok", "statement": verb, "sources": named,
                "rows_affected": affected}

    def list_alerts(self, status: str | None = None) -> list[dict[str, Any]]:
        """The alert queue, optionally one status, each alert with its events."""
        args: dict[str, Any] = {}
        found = self._alerts
        if status is not None:
            status = as_text("status", status).strip().lower()
            args["status"] = status
            found = [a for a in found if a["status"] == status]
        by_id = {e["id"]: e for e in self._events}
        result = [{**{k: v for k, v in a.items() if k != "events"},
                   "events": [copy.deepcopy(by_id[i]) for i in a["events"] if i in by_id]}
                  for a in found]
        self.log.record("list_alerts", args, copy.deepcopy(result))
        return result

    def update_alert(self, alert_id: str, status: str, note: str | None = None) -> dict[str, Any]:
        """Set an alert's status, with an optional triage note. In memory only."""
        alert_id = as_text("alert_id", alert_id).strip()
        status = as_text("status", status).strip().lower()
        if status not in ALERT_STATUSES:
            raise ToolArgumentError(f"status must be one of {', '.join(ALERT_STATUSES)}")
        alert = next((a for a in self._alerts if a["id"] == alert_id), None)
        if alert is None:
            raise ToolError(f"no alert {alert_id!r}")
        args: dict[str, Any] = {"alert_id": alert_id, "status": status}
        if note is not None:
            args["note"] = as_text("note", note)
        old, alert["status"] = alert["status"], status
        result = {"status": "updated", "alert_id": alert_id, "old": old, "new": status}
        self.log.record("update_alert", args, copy.deepcopy(result))
        return result

    def disable_rule(self, rule_id: str, reason: str) -> dict[str, Any]:
        """Turn a detection rule off. In memory only."""
        rule_id = as_text("rule_id", rule_id).strip()
        reason = as_text("reason", reason).strip()
        if not reason:
            raise ToolArgumentError("reason must say why the rule is turned off")
        rule = next((r for r in self._rules if r["id"] == rule_id), None)
        if rule is None:
            raise ToolError(f"no rule {rule_id!r}")
        was, rule["enabled"] = rule["enabled"], False
        result = {"status": "disabled" if was else "already disabled", "rule_id": rule_id,
                  "name": rule["name"]}
        self.log.record("disable_rule", {"rule_id": rule_id, "reason": reason},
                        copy.deepcopy(result))
        return result
