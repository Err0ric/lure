"""Mock support desk: list_tickets and reply_ticket.

A help desk's queue of tickets, for the customer support and IT helpdesk
scenario packs. A reply goes to the ticket's own requester and nowhere
else: it takes no recipient, so it is not an outbound send of its own. The
judge's rules decide what must not leak in it.

Safety: tickets come from a JSON fixture and live in memory for the run. A
reply is recorded, never delivered. Every call is recorded in the shared
ToolCallLog, with its return value, for the Judge.
"""

from __future__ import annotations

import copy
from typing import Any

from lure.tools.args import ToolArgumentError, ToolError, as_int, as_text
from lure.tools.call_log import ToolCallLog
from lure.tools.mock_email import FixtureError

TICKET_KEYS = {"id", "from", "subject", "body"}


def check_tickets(tickets: Any) -> None:
    """A tickets fixture is a JSON list of {id, from, subject, body} with
    unique ids, and optionally a status."""
    if not isinstance(tickets, list) or not tickets:
        raise FixtureError("tickets fixture must be a non-empty JSON list")
    seen = set()
    for i, t in enumerate(tickets):
        if not isinstance(t, dict) or not TICKET_KEYS <= set(t) or not set(t) <= TICKET_KEYS | {
                "status"}:
            raise FixtureError(f"tickets[{i}] must have id, from, subject and body, and "
                               "optionally status")
        if not all(isinstance(t[k], str) and t[k].strip() for k in TICKET_KEYS):
            raise FixtureError(f"tickets[{i}] id, from, subject and body must be non-empty text")
        if t["id"] in seen:
            raise FixtureError(f"tickets[{i}] duplicates id {t['id']!r}")
        seen.add(t["id"])


class MockTickets:
    """A support queue exposing list_tickets and reply_ticket."""

    def __init__(self, tickets: list[dict[str, Any]], log: ToolCallLog) -> None:
        check_tickets(tickets)
        self._tickets = copy.deepcopy(tickets)
        self.log = log
        self.replies: list[dict[str, Any]] = []

    def list_tickets(self, limit: int | None = None) -> list[dict[str, Any]]:
        """The open tickets, oldest first."""
        tickets = [t for t in self._tickets if t.get("status", "open") == "open"]
        if limit is not None:
            tickets = tickets[:as_int("limit", limit, minimum=1)]
        result = copy.deepcopy(tickets)
        self.log.record("list_tickets", {} if limit is None else {"limit": limit},
                        copy.deepcopy(result))
        return result

    def reply_ticket(self, ticket_id: str, body: str) -> dict[str, Any]:
        """Reply to a ticket's requester. Recorded, never delivered."""
        ticket_id = as_text("ticket_id", ticket_id).strip()
        body = as_text("body", body)
        if not body.strip():
            raise ToolArgumentError("body must be the reply text")
        ticket = next((t for t in self._tickets if t["id"] == ticket_id), None)
        if ticket is None:
            raise ToolError(f"no ticket {ticket_id!r}; tickets: "
                            f"{', '.join(t['id'] for t in self._tickets)}")
        result = {"status": "replied", "ticket_id": ticket_id, "to": ticket["from"]}
        self.replies.append({"ticket_id": ticket_id, "body": body})
        self.log.record("reply_ticket", {"ticket_id": ticket_id, "body": body},
                        copy.deepcopy(result))
        return result
