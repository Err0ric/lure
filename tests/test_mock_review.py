"""The mock code-review queue: list_pr_findings and set_finding_status. In
memory; every call is logged for the Judge."""

import copy
import json
from pathlib import Path

import pytest

from lure.tools.args import ToolArgumentError, ToolError
from lure.tools.call_log import ToolCallLog
from lure.tools.mock_email import FixtureError
from lure.tools.mock_review import MockReview, check_review

REPO = Path(__file__).resolve().parent.parent
REVIEW = json.loads((REPO / "fixtures" / "review_pr142.json").read_text(encoding="utf-8"))


def review():
    log = ToolCallLog()
    return MockReview(REVIEW, log), log


def test_the_shipped_fixture_is_valid():
    check_review(REVIEW)


@pytest.mark.parametrize("change, message", [
    (lambda d: d.pop("pr"), "pr and findings"),
    (lambda d: d.update(findings=[]), "non-empty list"),
    (lambda d: d["findings"][0].update(severity="urgent"), "severity"),
    (lambda d: d["findings"][0].update(status="ignored"), "status"),
    (lambda d: d["findings"][1].update(id="F-1"), "duplicates id"),
    (lambda d: d["findings"][0].pop("detail"), "must have"),
])
def test_check_review_rejects_bad_fixtures(change, message):
    bad = copy.deepcopy(REVIEW)
    change(bad)
    with pytest.raises(FixtureError, match=message):
        check_review(bad)


def test_list_pr_findings_returns_the_queue():
    mock, log = review()
    out = mock.list_pr_findings()
    assert out["pr"] == "142" and [f["id"] for f in out["findings"]] == ["F-1", "F-2", "F-3"]
    assert log.calls[0].tool == "list_pr_findings"


def test_set_finding_status_sets_and_validates():
    mock, log = review()
    assert mock.set_finding_status("F-3", "confirmed", "real")["new"] == "confirmed"
    assert mock.list_pr_findings()["findings"][2]["status"] == "confirmed"
    assert log.calls[0].args == {"finding_id": "F-3", "status": "confirmed", "note": "real"}
    with pytest.raises(ToolArgumentError, match="status must be one of"):
        mock.set_finding_status("F-1", "wontfix")
    with pytest.raises(ToolError, match="no finding"):
        mock.set_finding_status("F-9", "open")
