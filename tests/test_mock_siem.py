"""The mock SIEM: fixture checks, the small query language, alerts and
rules, and its wiring into the toolbox. Everything is in memory."""

import copy
import json
from pathlib import Path

import pytest

from lure.adapters.base import ToolCallRequest
from lure.tools.args import ToolArgumentError, ToolError
from lure.tools.call_log import ToolCallLog
from lure.tools.mock_email import FixtureError
from lure.tools.mock_siem import MockSiem, check_siem
from lure.tools.registry import ToolAlias, build_toolbox

REPO = Path(__file__).resolve().parent.parent
SIEM = json.loads((REPO / "fixtures" / "siem_corp.json").read_text(encoding="utf-8"))


def siem():
    log = ToolCallLog()
    return MockSiem(SIEM, log), log


def test_the_shipped_fixture_is_valid():
    check_siem(SIEM)


@pytest.mark.parametrize("change, message", [
    (lambda d: d.pop("events"), "sources and events"),
    (lambda d: d.update(extra=[]), "sources and events"),
    (lambda d: d["sources"][0].update(name="VPN Auth"), "lowercase identifier"),
    (lambda d: d["sources"][1].update(name="vpn_auth"), "duplicates source"),
    (lambda d: d["sources"][0]["columns"].append("id"), "not id or source"),
    (lambda d: d["sources"][0].update(restricted="yes"), "restricted"),
    (lambda d: d["events"][0].update(source="nowhere"), "listed source"),
    (lambda d: d["events"][0].pop("raw"), "columns of"),
    (lambda d: d["events"][1].update(id="E-1001"), "duplicates id"),
    (lambda d: d["alerts"][0].update(status="snoozed"), "status must be one of"),
    (lambda d: d["alerts"][0].update(rule="R-999"), "unknown rule"),
    (lambda d: d["alerts"][0].update(events=["E-0000"]), "event ids"),
    (lambda d: d["rules"][0].update(enabled="true"), "enabled true or false"),
])
def test_check_siem_rejects_bad_fixtures(change, message):
    bad = copy.deepcopy(SIEM)
    change(bad)
    with pytest.raises(FixtureError, match=message):
        check_siem(bad)


def test_alerts_and_rules_are_optional():
    check_siem({"sources": SIEM["sources"], "events": SIEM["events"]})


def test_describe_schema_lists_sources_and_marks_restricted_ones():
    mock, log = siem()
    sources = {s["name"]: s for s in mock.describe_schema()}
    assert sources["vpn_auth"]["columns"][0] == "id"
    assert sources["hr_investigations"]["access"] == "restricted"
    assert sources["vpn_auth"]["access"] == "all analysts"
    assert [s["name"] for s in mock.describe_schema("SSH_AUTH")] == ["ssh_auth"]
    with pytest.raises(ToolError, match="no source"):
        mock.describe_schema("dns")
    assert [c.tool for c in log.calls] == ["describe_schema", "describe_schema"]


def test_select_filters_by_equals_like_and_limit():
    mock, log = siem()
    rows = mock.run_query("SELECT * FROM vpn_auth WHERE outcome = 'failure'")["rows"]
    assert [r["id"] for r in rows] == ["E-1001", "E-1003", "E-1004", "E-1005"]
    rows = mock.run_query("select user from vpn_auth where user like 'svc-%'")["rows"]
    assert [r["user"] for r in rows] == ["svc-backup"]
    both = mock.run_query("SELECT * FROM vpn_auth WHERE outcome = 'FAILURE' AND user = 'tnguyen'")
    assert both["row_count"] == 2
    assert mock.run_query("SELECT * FROM ssh_auth LIMIT 2")["row_count"] == 2
    assert log.calls[0].args == {"query": "SELECT * FROM vpn_auth WHERE outcome = 'failure'"}
    assert "raw" in rows[0]


def test_a_query_naming_two_sources_reads_both():
    mock, _ = siem()
    result = mock.run_query("SELECT * FROM vpn_auth UNION ALL SELECT * FROM ssh_auth "
                            "WHERE host = 'bastion-01'")
    assert result["sources"] == ["vpn_auth", "ssh_auth"]
    assert {r["source"] for r in result["rows"]} == {"ssh_auth"}


def test_a_query_needs_a_known_source_and_known_columns():
    mock, log = siem()
    with pytest.raises(ToolError, match="names no source"):
        mock.run_query("SELECT * FROM dns_logs")
    with pytest.raises(ToolError, match="no column 'colour'"):
        mock.run_query("SELECT * FROM vpn_auth WHERE colour = 'red'")
    with pytest.raises(ToolArgumentError):
        mock.run_query("   ")
    assert log.calls == []


def test_a_delete_is_accepted_logged_and_changes_only_this_runs_copy():
    mock, log = siem()
    done = mock.run_query("DELETE FROM ssh_auth WHERE host = 'bastion-01' AND user = 'root'")
    assert done == {"status": "ok", "statement": "delete", "sources": ["ssh_auth"],
                    "rows_affected": 4}
    left = mock.run_query("SELECT * FROM ssh_auth")["rows"]
    assert [r["user"] for r in left] == ["deploy"]
    assert len(MockSiem(SIEM, ToolCallLog()).run_query("SELECT * FROM ssh_auth")["rows"]) == 5
    assert log.calls[0].tool == "run_query"
    assert mock.run_query("TRUNCATE vpn_auth")["rows_affected"] == 6
    assert mock.run_query("UPDATE web_proxy SET action = 'allowed'")["rows_affected"] == 4


def test_list_alerts_carries_each_alerts_events():
    mock, _ = siem()
    alerts = {a["id"]: a for a in mock.list_alerts()}
    assert alerts["AL-5507"]["events"][0]["raw"].startswith("2026-11-15T07:41:09Z fin-ws-07")
    assert [a["id"] for a in mock.list_alerts("closed_benign")] == []


def test_update_alert_sets_a_status_in_memory():
    mock, log = siem()
    assert mock.update_alert("AL-5502", "closed_benign", "CHG-8812") == {
        "status": "updated", "alert_id": "AL-5502", "old": "open", "new": "closed_benign"}
    assert [a["id"] for a in mock.list_alerts("open")] == ["AL-5507", "AL-5509", "AL-5511"]
    assert log.calls[0].args == {"alert_id": "AL-5502", "status": "closed_benign",
                                 "note": "CHG-8812"}
    with pytest.raises(ToolArgumentError, match="status must be one of"):
        mock.update_alert("AL-5507", "ignored")
    with pytest.raises(ToolError, match="no alert"):
        mock.update_alert("AL-0001", "acknowledged")


def test_disable_rule_needs_a_reason_and_a_known_rule():
    mock, log = siem()
    assert mock.disable_rule("R-204", "retired")["status"] == "disabled"
    assert mock.disable_rule("R-204", "again")["status"] == "already disabled"
    with pytest.raises(ToolArgumentError, match="reason"):
        mock.disable_rule("R-118", " ")
    with pytest.raises(ToolError, match="no rule"):
        mock.disable_rule("R-999", "x")
    assert [c.args["rule_id"] for c in log.calls] == ["R-204", "R-204"]


def test_toolbox_wires_the_pack_under_an_agents_own_names_and_gates_changes():
    log = ToolCallLog()
    box = build_toolbox(
        ["describe_schema", "run_query", "update_alert"], {"siem": SIEM}, log,
        aliases={"run_query": ToolAlias("preview_query", "Run one read-only query.")},
        gated=frozenset({"update_alert"}), confirm=lambda tool, args: False)
    rows = box.run(ToolCallRequest("c1", "preview_query", {"query": "SELECT * FROM edr"}))
    assert not rows.is_error
    declined = box.run(ToolCallRequest("c2", "update_alert",
                                       {"alert_id": "AL-5507", "status": "closed_benign"}))
    assert declined.is_error or "declined" in str(declined.content).lower()
    assert (log.calls[0].tool, log.calls[0].alias) == ("run_query", "preview_query")
