"""Mock HR system: list_candidates, lookup_employee and update_direct_deposit.

For the HR and recruiting scenario pack: job applications with their
resume text, and employee records, so an agent can review candidates, look
up a new hire, or change where their pay goes.

Safety: candidates and employees come from a JSON fixture and live in memory
for the run. A deposit change updates only that copy; no payroll system or
bank exists. Every call is recorded in the shared ToolCallLog, with its
return value, for the Judge.
"""

from __future__ import annotations

import copy
import re
from typing import Any

from lure.tools.args import ToolArgumentError, ToolError, as_text
from lure.tools.call_log import ToolCallLog
from lure.tools.mock_email import FixtureError

CANDIDATE_KEYS = {"id", "name", "email", "role", "stage", "resume"}
EMPLOYEE_KEYS = {"id", "name", "email", "title", "manager", "start_date", "onboarding",
                 "salary", "deposit_last4"}
LAST4_RE = re.compile(r"^\d{4}$")
# A bank account number as people type it: digits with dashes or spaces.
ACCOUNT_RE = re.compile(r"^\d[\d\- ]{5,22}\d$")


def check_hr(hr: Any) -> None:
    """An hr fixture is {candidates, employees}: candidates with id, name,
    email, role, stage and resume; employees with id, name, email, title,
    manager, start_date, onboarding, salary and deposit_last4."""
    if not isinstance(hr, dict) or set(hr) != {"candidates", "employees"}:
        raise FixtureError("hr fixture must be an object with candidates and employees")
    for kind, keys in (("candidates", CANDIDATE_KEYS), ("employees", EMPLOYEE_KEYS)):
        items = hr[kind]
        if not isinstance(items, list):
            raise FixtureError(f"hr {kind} must be a list")
        seen = set()
        for i, item in enumerate(items):
            if not isinstance(item, dict) or set(item) != keys:
                raise FixtureError(f"hr {kind}[{i}] must have {', '.join(sorted(keys))}")
            if not all(isinstance(v, str) for v in item.values()):
                raise FixtureError(f"hr {kind}[{i}] fields must be strings")
            if item["id"] in seen:
                raise FixtureError(f"hr {kind}[{i}] duplicates id {item['id']!r}")
            seen.add(item["id"])
            if kind == "employees" and not LAST4_RE.match(item["deposit_last4"]):
                raise FixtureError(f"hr employees[{i}].deposit_last4 must be 4 digits")
    if not hr["candidates"] and not hr["employees"]:
        raise FixtureError("hr fixture needs candidates or employees")


class MockHr:
    """Candidates and employee records exposing list_candidates,
    lookup_employee and update_direct_deposit."""

    def __init__(self, hr: dict[str, Any], log: ToolCallLog) -> None:
        check_hr(hr)
        self._hr = copy.deepcopy(hr)
        self.log = log

    def list_candidates(self, role: str | None = None) -> list[dict[str, Any]]:
        """Applications, optionally for one role, with their resume text."""
        args: dict[str, Any] = {}
        found = self._hr["candidates"]
        if role is not None:
            role = as_text("role", role).strip()
            args["role"] = role
            found = [c for c in found if role.lower() in c["role"].lower()]
        result = copy.deepcopy(found)
        self.log.record("list_candidates", args, copy.deepcopy(result))
        return result

    def lookup_employee(self, query: str) -> dict[str, Any]:
        """An employee by id, email, or all or part of their name."""
        query = as_text("query", query).strip().lower()
        found = next((e for e in self._hr["employees"] if query in (
            e["id"].lower(), e["email"].lower()) or (query and query in e["name"].lower())),
            None)
        if found is None:
            raise ToolError(f"no employee matches {query!r}")
        result = copy.deepcopy(found)
        self.log.record("lookup_employee", {"query": query}, copy.deepcopy(result))
        return result

    def update_direct_deposit(self, employee_id: str, account: str) -> dict[str, Any]:
        """Change the bank account an employee's pay goes to. In memory only."""
        employee_id = as_text("employee_id", employee_id).strip()
        account = as_text("account", account).strip()
        if not ACCOUNT_RE.match(account):
            raise ToolArgumentError("account must be a bank account number")
        employee = next((e for e in self._hr["employees"] if e["id"] == employee_id), None)
        if employee is None:
            raise ToolError(f"no employee {employee_id!r}")
        old = employee["deposit_last4"]
        employee["deposit_last4"] = re.sub(r"\D", "", account)[-4:]
        result = {"status": "updated", "employee_id": employee_id, "old_last4": old,
                  "new_last4": employee["deposit_last4"]}
        self.log.record("update_direct_deposit", {"employee_id": employee_id,
                                                  "account": account}, copy.deepcopy(result))
        return result
