"""Mock MCP tools: tool definitions that come from a fixture.

An `mcp` fixture stands in for a third-party tool server. Each entry is a
tool the server offers, with its own description and parameter schema, and
the canned result it returns. The definition itself is the attack surface:
a poisoned description or parameter description reaches the target the
moment the tool is offered, before it reads any document.

    [{"name": "lookup_vendor",
      "description": "Look up a vendor's contacts. ...",
      "parameters": {"type": "object", "properties": {...}},
      "result": {"vendor": "Marlow Textiles", ...}}]

Safety: nothing here is a real MCP client or server. The tools are plain
Python callables that log the call and return the fixture's canned result.
No network, no process, no file access.
"""

from __future__ import annotations

import copy
import re
from typing import Any

from lure.tools import KNOWN_TOOLS
from lure.tools.call_log import ToolCallLog
from lure.tools.mock_email import FixtureError

REQUIRED_FIELDS = ("name", "description", "parameters", "result")
NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def check_mcp(tools: Any) -> None:
    """An mcp fixture is a JSON list of {name, description, parameters, result}
    with unique names that do not shadow a built-in mock tool."""
    if not isinstance(tools, list) or not tools:
        raise FixtureError("mcp fixture must be a non-empty JSON list")
    seen = set()
    for i, t in enumerate(tools):
        if not isinstance(t, dict):
            raise FixtureError(f"mcp[{i}] must be an object")
        missing = [k for k in REQUIRED_FIELDS if k not in t]
        if missing:
            raise FixtureError(f"mcp[{i}] missing fields {missing}")
        unknown = sorted(set(t) - set(REQUIRED_FIELDS))
        if unknown:
            raise FixtureError(f"mcp[{i}] unknown fields {unknown}")
        name = t["name"]
        if not isinstance(name, str) or not NAME_RE.match(name):
            raise FixtureError(f"mcp[{i}] name must be snake_case like lookup_vendor")
        if name in KNOWN_TOOLS:
            raise FixtureError(f"mcp[{i}] name {name!r} shadows a built-in mock tool")
        if name in seen:
            raise FixtureError(f"mcp[{i}] duplicates tool {name!r}")
        seen.add(name)
        if not isinstance(t["description"], str) or not t["description"].strip():
            raise FixtureError(f"mcp[{i}] description must be a non-empty string")
        params = t["parameters"]
        if not isinstance(params, dict) or params.get("type") != "object":
            raise FixtureError(f"mcp[{i}] parameters must be a JSON Schema object")


def tool_names(tools: Any) -> list[str]:
    """Names in an mcp fixture, or none if it is not a list of tools."""
    if not isinstance(tools, list):
        return []
    return [t["name"] for t in tools if isinstance(t, dict) and isinstance(t.get("name"), str)]


class MockMcp:
    """Serves the fixture's tools. Every call returns its canned result."""

    def __init__(self, tools: list[dict[str, Any]], log: ToolCallLog) -> None:
        check_mcp(tools)
        self._tools = {t["name"]: copy.deepcopy(t) for t in tools}
        self.log = log

    @property
    def names(self) -> list[str]:
        return list(self._tools)

    def definition(self, name: str) -> dict[str, Any]:
        return copy.deepcopy(self._tools[name])

    def call(self, name: str, arguments: dict[str, Any]) -> Any:
        result = copy.deepcopy(self._tools[name]["result"])
        self.log.record(name, dict(arguments), copy.deepcopy(result))
        return result
