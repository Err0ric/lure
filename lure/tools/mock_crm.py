"""Mock CRM: list_deals, lookup_account and update_account.

For the sales scenario pack: customer accounts with their contacts and
notes, and the open pipeline, so an agent can review deals, look up an
account, or change its billing contact.

Safety: accounts and deals come from a JSON fixture and live in memory for
the run. An update changes only that copy; no CRM exists. Every call is
recorded in the shared ToolCallLog, with its return value, for the Judge.
"""

from __future__ import annotations

import copy
from typing import Any

from lure.tools.args import ToolArgumentError, ToolError, as_text
from lure.tools.call_log import ToolCallLog
from lure.tools.mock_email import FixtureError

ACCOUNT_KEYS = {"id", "name", "domain", "billing_contact", "contacts", "notes"}
CONTACT_KEYS = {"name", "email", "title"}
NOTE_KEYS = {"date", "author", "text"}
DEAL_KEYS = {"id", "account", "name", "amount", "stage", "close_date", "owner"}
# Billing contact details an agent may change.
BILLING_FIELDS = ("billing_contact_name", "billing_contact_email", "billing_contact_phone")


def _strings(item: dict[str, Any], where: str) -> None:
    if not all(isinstance(v, str) for v in item.values()):
        raise FixtureError(f"{where} fields must be strings")


def check_crm(crm: Any) -> None:
    """A crm fixture is {accounts, deals}: accounts with id, name, domain,
    billing_contact {name, email, phone}, contacts {name, email, title} and
    notes {date, author, text}; deals with id, account, name, amount, stage,
    close_date and owner, each on a listed account."""
    if not isinstance(crm, dict) or set(crm) != {"accounts", "deals"}:
        raise FixtureError("crm fixture must be an object with accounts and deals")
    accounts, deals = crm["accounts"], crm["deals"]
    if not isinstance(accounts, list) or not accounts or not isinstance(deals, list):
        raise FixtureError("crm accounts must be a non-empty list, and deals a list")
    ids = set()
    for i, a in enumerate(accounts):
        where = f"crm accounts[{i}]"
        if not isinstance(a, dict) or set(a) != ACCOUNT_KEYS:
            raise FixtureError(f"{where} must have {', '.join(sorted(ACCOUNT_KEYS))}")
        if a["id"] in ids:
            raise FixtureError(f"{where} duplicates id {a['id']!r}")
        ids.add(a["id"])
        billing = a["billing_contact"]
        if not isinstance(billing, dict) or set(billing) != {"name", "email", "phone"}:
            raise FixtureError(f"{where}.billing_contact must have name, email and phone")
        _strings(billing, f"{where}.billing_contact")
        for key, keys in (("contacts", CONTACT_KEYS), ("notes", NOTE_KEYS)):
            if not isinstance(a[key], list):
                raise FixtureError(f"{where}.{key} must be a list")
            for j, item in enumerate(a[key]):
                if not isinstance(item, dict) or set(item) != keys:
                    raise FixtureError(f"{where}.{key}[{j}] must have "
                                       f"{', '.join(sorted(keys))}")
                _strings(item, f"{where}.{key}[{j}]")
    seen = set()
    for i, d in enumerate(deals):
        where = f"crm deals[{i}]"
        if not isinstance(d, dict) or set(d) != DEAL_KEYS:
            raise FixtureError(f"{where} must have {', '.join(sorted(DEAL_KEYS))}")
        _strings(d, where)
        if d["id"] in seen:
            raise FixtureError(f"{where} duplicates id {d['id']!r}")
        seen.add(d["id"])
        if d["account"] not in ids:
            raise FixtureError(f"{where} names unknown account {d['account']!r}")


class MockCrm:
    """Accounts and deals exposing list_deals, lookup_account and
    update_account."""

    def __init__(self, crm: dict[str, Any], log: ToolCallLog) -> None:
        check_crm(crm)
        self._crm = copy.deepcopy(crm)
        self.log = log

    def list_deals(self, stage: str | None = None) -> list[dict[str, Any]]:
        """The open pipeline, optionally one stage."""
        args: dict[str, Any] = {}
        found = self._crm["deals"]
        if stage is not None:
            stage = as_text("stage", stage).strip()
            args["stage"] = stage
            found = [d for d in found if d["stage"].lower() == stage.lower()]
        result = copy.deepcopy(found)
        self.log.record("list_deals", args, copy.deepcopy(result))
        return result

    def lookup_account(self, query: str) -> dict[str, Any]:
        """An account by id, domain, or all or part of its name, with its
        contacts and notes."""
        query = as_text("query", query).strip().lower()
        found = next((a for a in self._crm["accounts"] if query in (
            a["id"].lower(), a["domain"].lower()) or (query and query in a["name"].lower())),
            None)
        if found is None:
            raise ToolError(f"no account matches {query!r}")
        result = copy.deepcopy(found)
        self.log.record("lookup_account", {"query": query}, copy.deepcopy(result))
        return result

    def update_account(self, account_id: str, field: str, value: str) -> dict[str, Any]:
        """Change one billing contact detail on an account. In memory only."""
        account_id = as_text("account_id", account_id).strip()
        field, value = as_text("field", field).strip(), as_text("value", value).strip()
        if field not in BILLING_FIELDS:
            raise ToolArgumentError(f"field must be one of {', '.join(BILLING_FIELDS)}")
        if not value:
            raise ToolArgumentError("value must be the new detail")
        account = next((a for a in self._crm["accounts"] if a["id"] == account_id), None)
        if account is None:
            raise ToolError(f"no account {account_id!r}")
        key = field.removeprefix("billing_contact_")
        old = account["billing_contact"][key]
        account["billing_contact"][key] = value
        result = {"status": "updated", "account_id": account_id, "field": field, "old": old,
                  "new": value}
        self.log.record("update_account", {"account_id": account_id, "field": field,
                                           "value": value}, copy.deepcopy(result))
        return result
