"""Mock email tools: read_inbox and send_email.

Safety: this module never touches the network. The inbox comes from a JSON
fixture, and send_email only appends to an in-memory outbox. Every call is
recorded in the shared ToolCallLog, with its return value, for the Judge.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from lure.tools.args import as_int, as_str_list, as_text
from lure.tools.call_log import ToolCallLog

REQUIRED_FIELDS = ("from", "to", "subject", "body")


class FixtureError(ValueError):
    """Raised when an inbox fixture is missing or malformed."""


def load_inbox(path: str | Path) -> list[dict[str, Any]]:
    """Load an inbox fixture: a JSON list of message objects."""
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise FixtureError(f"inbox fixture not found: {path}") from e
    except json.JSONDecodeError as e:
        raise FixtureError(f"inbox fixture is not valid JSON: {path}: {e}") from e

    if not isinstance(data, list):
        raise FixtureError(f"inbox fixture must be a JSON list: {path}")
    for i, msg in enumerate(data):
        if not isinstance(msg, dict):
            raise FixtureError(f"inbox[{i}] must be an object: {path}")
        missing = [f for f in REQUIRED_FIELDS if f not in msg]
        if missing:
            raise FixtureError(f"inbox[{i}] missing fields {missing}: {path}")
    return data


class MockEmail:
    """In-memory mailbox exposing read_inbox and send_email to a target."""

    def __init__(self, inbox: list[dict[str, Any]], log: ToolCallLog) -> None:
        self._inbox = copy.deepcopy(inbox)
        self.log = log
        self.outbox: list[dict[str, Any]] = []

    @classmethod
    def from_fixture(cls, path: str | Path, log: ToolCallLog) -> MockEmail:
        return cls(load_inbox(path), log)

    def read_inbox(self, limit: int | str | None = None) -> list[dict[str, Any]]:
        """Return inbox messages in fixture order.

        Returns copies so the target cannot alter the fixture. Raises
        ToolArgumentError for a limit that is not a whole number >= 0.
        """
        if limit is not None:
            limit = as_int("limit", limit, minimum=0)
        messages = self._inbox if limit is None else self._inbox[:limit]
        result = copy.deepcopy(messages)
        self.log.record("read_inbox", {"limit": limit}, result)
        return result

    def send_email(
        self,
        to: str | list[str],
        subject: str,
        body: str,
        cc: str | list[str] | None = None,
        bcc: str | list[str] | None = None,
    ) -> dict[str, Any]:
        """Pretend to send an email. Nothing leaves the process.

        cc and bcc are optional and only logged when given.
        """
        message: dict[str, Any] = {"to": as_str_list("to", to)}
        for name, value in (("cc", cc), ("bcc", bcc)):
            if value not in (None, []):
                message[name] = as_str_list(name, value)
        message["subject"] = as_text("subject", subject)
        message["body"] = as_text("body", body)
        message_id = f"mock-{len(self.outbox) + 1}"
        self.outbox.append({"id": message_id, **message})
        result = {"status": "sent", "id": message_id}
        self.log.record("send_email", dict(message), result)
        return result
