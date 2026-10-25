"""Mock environment tool: list_env.

Safety: this module never reads the real process environment. Variables
come from a JSON fixture and live in memory for the run; every value named
like a secret is a LURE-FAKE- canary (checked when the attack loads). The
tool is read-only. Every call is recorded in the shared ToolCallLog, with
its return value, for the Judge.
"""

from __future__ import annotations

import copy
import re
from typing import Any

from lure.tools.args import as_text
from lure.tools.call_log import ToolCallLog
from lure.tools.mock_email import FixtureError

NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def check_env(variables: Any) -> None:
    """An env fixture is a JSON list of {name, value} with unique names."""
    if not isinstance(variables, list):
        raise FixtureError("env fixture must be a JSON list")
    seen = set()
    for i, v in enumerate(variables):
        if not isinstance(v, dict) or set(v) != {"name", "value"}:
            raise FixtureError(f"env[{i}] must be an object with name and value")
        if not isinstance(v["name"], str) or not NAME_RE.match(v["name"]):
            raise FixtureError(f"env[{i}] name must be a variable name like ERP_BASE_URL")
        if not isinstance(v["value"], str):
            raise FixtureError(f"env[{i}] value must be a string")
        if v["name"] in seen:
            raise FixtureError(f"env[{i}] duplicates name {v['name']!r}")
        seen.add(v["name"])


class MockEnv:
    """The agent's environment variables, from a fixture."""

    def __init__(self, variables: list[dict[str, str]], log: ToolCallLog) -> None:
        check_env(variables)
        self._vars = copy.deepcopy(variables)
        self.log = log

    def list_env(self, prefix: str | None = None) -> list[dict[str, str]]:
        """Return the variables in fixture order, optionally only names that
        start with prefix (any case: models often lowercase it)."""
        if prefix is not None:
            prefix = as_text("prefix", prefix).strip()
        wanted = (prefix or "").upper()
        result = [dict(v) for v in self._vars if v["name"].upper().startswith(wanted)]
        self.log.record("list_env", {"prefix": prefix}, copy.deepcopy(result))
        return result
