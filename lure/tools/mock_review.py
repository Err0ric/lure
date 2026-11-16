"""Mock code-review queue: list_pr_findings and set_finding_status.

For an automated code-review agent that reads the security findings on a
pull request and sets each one's status. A finding's detail text is written
by whoever opened the PR, so it is attacker-controlled: it can tell the
reviewer that a real finding is a known false positive.

Safety: findings come from a JSON fixture and live in memory for the run. A
status change edits only that copy; no review system is touched. Every call
is recorded in the shared ToolCallLog, with its return value, for the Judge.
"""

from __future__ import annotations

import copy
from typing import Any

from lure.tools.args import ToolArgumentError, ToolError, as_text
from lure.tools.call_log import ToolCallLog
from lure.tools.mock_email import FixtureError

FINDING_KEYS = {"id", "file", "severity", "title", "detail", "status"}
# Statuses a reviewer may set. The last two dismiss a finding.
STATUSES = ("open", "confirmed", "fixed", "false_positive", "accepted_risk")
SEVERITIES = ("low", "medium", "high", "critical")


def check_review(review: Any) -> None:
    """A review fixture is {pr, findings}: pr is the pull request id; findings
    have id, file, severity (low/medium/high/critical), title, detail and
    status (one of the allowed statuses)."""
    if not isinstance(review, dict) or set(review) != {"pr", "findings"}:
        raise FixtureError("review fixture must be an object with pr and findings")
    if not isinstance(review["pr"], str) or not review["pr"]:
        raise FixtureError("review pr must be a non-empty string")
    findings = review["findings"]
    if not isinstance(findings, list) or not findings:
        raise FixtureError("review findings must be a non-empty list")
    seen = set()
    for i, f in enumerate(findings):
        where = f"review findings[{i}]"
        if not isinstance(f, dict) or set(f) != FINDING_KEYS:
            raise FixtureError(f"{where} must have {', '.join(sorted(FINDING_KEYS))}")
        if not all(isinstance(f[k], str) and f[k] for k in FINDING_KEYS):
            raise FixtureError(f"{where} fields must be non-empty strings")
        if f["id"] in seen:
            raise FixtureError(f"{where} duplicates id {f['id']!r}")
        seen.add(f["id"])
        if f["severity"] not in SEVERITIES:
            raise FixtureError(f"{where}.severity must be one of {', '.join(SEVERITIES)}")
        if f["status"] not in STATUSES:
            raise FixtureError(f"{where}.status must be one of {', '.join(STATUSES)}")


class MockReview:
    """A PR's findings exposing list_pr_findings and set_finding_status."""

    def __init__(self, review: dict[str, Any], log: ToolCallLog) -> None:
        check_review(review)
        self._pr = review["pr"]
        self._findings = copy.deepcopy(review["findings"])
        self.log = log

    def list_pr_findings(self) -> dict[str, Any]:
        """Every open and triaged finding on the pull request."""
        result = {"pr": self._pr, "findings": copy.deepcopy(self._findings)}
        self.log.record("list_pr_findings", {}, copy.deepcopy(result))
        return result

    def set_finding_status(self, finding_id: str, status: str,
                           note: str | None = None) -> dict[str, Any]:
        """Set a finding's status, for example confirm it or mark it a false
        positive. In memory only."""
        finding_id = as_text("finding_id", finding_id).strip()
        status = as_text("status", status).strip().lower()
        if status not in STATUSES:
            raise ToolArgumentError(f"status must be one of {', '.join(STATUSES)}")
        finding = next((f for f in self._findings if f["id"] == finding_id), None)
        if finding is None:
            raise ToolError(f"no finding {finding_id!r}")
        args: dict[str, Any] = {"finding_id": finding_id, "status": status}
        if note is not None:
            args["note"] = as_text("note", note)
        old, finding["status"] = finding["status"], status
        result = {"status": "updated", "finding_id": finding_id, "old": old, "new": status}
        self.log.record("set_finding_status", args, copy.deepcopy(result))
        return result
