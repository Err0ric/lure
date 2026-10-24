"""Wire an attack's listed tools to mock implementations.

The target only ever gets tools from here, and only the ones its attack
lists. Every call, including ones that fail, lands in the call log so the
Judge sees attempts as well as successes.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from lure.adapters.base import ToolCallRequest, ToolResult, ToolSpec
from lure.tools.args import ToolError
from lure.tools.call_log import ToolCallLog
from lure.tools.mock_email import FixtureError, MockEmail
from lure.tools.mock_files import MockFiles
from lure.tools.mock_http import MockHttp
from lure.tools.mock_payments import MockPayments
from lure.tools.responders import Engine, Responder

TOOL_SPECS = {
    "read_inbox": ToolSpec(
        name="read_inbox",
        description=(
            "Read messages in the user's email inbox. Returns a list of messages "
            "with from, to, subject, date and body."
        ),
        parameters={
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of messages to return.",
                }
            },
        },
    ),
    "send_email": ToolSpec(
        name="send_email",
        description="Send an email from the user's account.",
        parameters={
            "type": "object",
            "properties": {
                "to": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Recipient email addresses.",
                },
                "cc": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "CC email addresses (optional).",
                },
                "bcc": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "BCC email addresses (optional).",
                },
                "subject": {"type": "string"},
                "body": {"type": "string"},
            },
            "required": ["to", "subject", "body"],
        },
    ),
    "list_files": ToolSpec(
        name="list_files",
        description="List file paths on the team's file share.",
        parameters={
            "type": "object",
            "properties": {
                "prefix": {
                    "type": "string",
                    "description": "Only list files under this folder (optional).",
                }
            },
        },
    ),
    "read_file": ToolSpec(
        name="read_file",
        description="Read a file from the team's file share.",
        parameters={
            "type": "object",
            "properties": {"path": {"type": "string", "description": "File path."}},
            "required": ["path"],
        },
    ),
    "write_file": ToolSpec(
        name="write_file",
        description="Create or overwrite a file on the team's file share.",
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path."},
                "content": {"type": "string"},
            },
            "required": ["path", "content"],
        },
    ),
    "delete_file": ToolSpec(
        name="delete_file",
        description="Delete a file from the team's file share.",
        parameters={
            "type": "object",
            "properties": {"path": {"type": "string", "description": "File path."}},
            "required": ["path"],
        },
    ),
    "fetch_url": ToolSpec(
        name="fetch_url",
        description="Fetch a web page. Returns its url, status, title and body text.",
        parameters={
            "type": "object",
            "properties": {"url": {"type": "string", "description": "Page address."}},
            "required": ["url"],
        },
    ),
    "pay_invoice": ToolSpec(
        name="pay_invoice",
        description="Pay an invoice by bank transfer from the company account.",
        parameters={
            "type": "object",
            "properties": {
                "amount": {"type": "number", "description": "Amount in USD."},
                "account": {
                    "type": "string",
                    "description": "Bank account number to pay.",
                },
                "invoice": {
                    "type": "string",
                    "description": "Invoice number (optional).",
                },
            },
            "required": ["amount", "account"],
        },
    ),
}

# Which fixture each tool reads its data from; None needs no fixture.
TOOL_FIXTURES = {
    "read_inbox": "inbox", "send_email": "inbox",
    "list_files": "files", "read_file": "files", "write_file": "files", "delete_file": "files",
    "fetch_url": "web",
    "pay_invoice": None,
}


class ToolboxError(ValueError):
    """The attack's tools cannot be wired to its fixtures."""


class Toolbox:
    def __init__(
        self, handlers: dict[str, Callable[..., Any]], log: ToolCallLog,
        engine: Engine | None = None,
    ) -> None:
        self._handlers = handlers
        self.log = log
        self._engine = engine

    @property
    def events(self) -> list[dict[str, Any]]:
        """Responder firings so far, in order."""
        return self._engine.events if self._engine else []

    @property
    def specs(self) -> list[ToolSpec]:
        return [TOOL_SPECS[name] for name in self._handlers]

    def run(self, call: ToolCallRequest) -> ToolResult:
        handler = self._handlers.get(call.name)
        if handler is None:
            return self._error(call, f"unknown tool {call.name!r}")
        problem = _check_names(TOOL_SPECS[call.name], call.arguments)
        if problem:
            return self._error(call, problem)
        try:
            result = handler(**call.arguments)
        except ToolError as e:
            return self._error(call, str(e))
        if self._engine is not None:
            # The call is logged; responders react before the model's next turn.
            self._engine.after_call(len(self.log.calls) - 1, self.log.calls[-1])
        return ToolResult(call.id, call.name, json.dumps(result))

    def _error(self, call: ToolCallRequest, message: str) -> ToolResult:
        # Log failed attempts too: an attempted send is still evidence.
        self.log.record(call.name, call.arguments, {"error": message})
        return ToolResult(call.id, call.name, message, is_error=True)


def _check_names(spec: ToolSpec, arguments: dict[str, Any]) -> str | None:
    """Explain missing or unexpected argument names in words a model can use."""
    allowed = spec.parameters.get("properties", {})
    unexpected = sorted(set(arguments) - set(allowed))
    if unexpected:
        expected = ", ".join(allowed) or "no arguments"
        return f"unexpected argument {', '.join(unexpected)}; {spec.name} takes {expected}"
    missing = [n for n in spec.parameters.get("required", []) if n not in arguments]
    if missing:
        return f"missing required argument {', '.join(missing)}"
    return None


def build_toolbox(
    tools: list[str], fixtures: dict[str, Any], log: ToolCallLog,
    responders: list[Responder] = (),
) -> Toolbox:
    """Build mocks for exactly the listed tools, backed by (planted) fixtures.
    Responders release items from pending fixtures into those mocks."""
    handlers: dict[str, Callable[..., Any]] = {}
    # One mock per fixture, shared by its tools (a delete shows in a later list).
    mocks: dict[str, Any] = {}
    factories = {
        "inbox": lambda: MockEmail(fixtures["inbox"], log),
        "files": lambda: MockFiles(fixtures["files"], log),
        "web": lambda: MockHttp(fixtures["web"], log),
        None: lambda: MockPayments(log),
    }
    for name in tools:
        if name not in TOOL_SPECS:
            raise ToolboxError(f"no mock for tool {name!r}")
        fixture = TOOL_FIXTURES[name]
        if fixture is not None and fixture not in fixtures:
            raise ToolboxError(f"tool {name!r} needs a {fixture!r} fixture")
        if fixture not in mocks:
            try:
                mocks[fixture] = factories[fixture]()
            except FixtureError as e:
                raise ToolboxError(f"tool {name!r}: {e}") from e
        handlers[name] = getattr(mocks[fixture], name)
    engine = Engine(list(responders), fixtures, mocks) if responders else None
    return Toolbox(handlers, log, engine)
