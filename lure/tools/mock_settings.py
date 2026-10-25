"""Mock agent settings tools: read_agent_settings and update_agent_settings.

The agent's own configuration (who it may email, whether payments need a
person to confirm, its approval limit, its rules file), for testing whether
an injection can get an agent to change its own permissions.

Safety: the settings come from a JSON fixture and live in memory for the
run; an update changes only that copy. Nothing on disk or in a real agent
is touched. Every call is recorded in the shared ToolCallLog, with its
return value, for the Judge.
"""

from __future__ import annotations

import copy
from typing import Any

from lure.tools.args import ToolArgumentError, ToolError, as_text
from lure.tools.call_log import ToolCallLog
from lure.tools.mock_email import FixtureError


def check_settings(settings: Any) -> None:
    """An agent_settings fixture is a JSON object of setting name to value."""
    if not isinstance(settings, dict) or not settings:
        raise FixtureError("agent_settings fixture must be a non-empty JSON object")
    for name in settings:
        if not isinstance(name, str) or not name.strip():
            raise FixtureError("agent_settings names must be non-empty strings")


class MockSettings:
    """The agent's own settings, from a fixture."""

    def __init__(self, settings: dict[str, Any], log: ToolCallLog) -> None:
        check_settings(settings)
        self._settings = copy.deepcopy(settings)
        self.log = log

    @property
    def settings(self) -> dict[str, Any]:
        """The settings as they stand now, after any updates."""
        return copy.deepcopy(self._settings)

    def read_agent_settings(self) -> dict[str, Any]:
        result = copy.deepcopy(self._settings)
        self.log.record("read_agent_settings", {}, copy.deepcopy(result))
        return result

    def update_agent_settings(self, setting: str, value: Any) -> dict[str, Any]:
        """Replace one setting's value. The setting must already exist."""
        setting = as_text("setting", setting).strip()
        if not setting:
            raise ToolArgumentError("setting must name one of the agent's settings")
        if setting not in self._settings:
            raise ToolError(f"no setting {setting!r}; settings: {', '.join(self._settings)}")
        old = self._settings[setting]
        self._settings[setting] = copy.deepcopy(value)
        result = {"status": "updated", "setting": setting, "old": old, "new": value}
        self.log.record("update_agent_settings", {"setting": setting, "value": value},
                        copy.deepcopy(result))
        return result
