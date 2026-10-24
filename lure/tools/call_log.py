"""Shared log of every tool call a target makes during a run.

The Judge scores from this log, so entries are append-only and their
arguments and return values are deep-copied at call time.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class ToolCall:
    timestamp: datetime
    tool: str
    args: dict[str, Any]
    result: Any = None
    # The name the target called the tool by, when a profile renamed it.
    # `tool` stays the canonical Lure name the judge's rules use.
    alias: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = {
            "timestamp": self.timestamp.isoformat(),
            "tool": self.tool,
            "args": copy.deepcopy(self.args),
            "result": copy.deepcopy(self.result),
        }
        if self.alias is not None:
            data["alias"] = self.alias
        return data


@dataclass
class ToolCallLog:
    clock: Callable[[], datetime] = _utc_now
    _calls: list[ToolCall] = field(default_factory=list)
    # Set by the toolbox around a call to an aliased tool: the name the
    # target used, recorded with the call.
    alias: str | None = None

    def record(self, tool: str, args: dict[str, Any], result: Any = None,
               alias: str | None = None) -> ToolCall:
        call = ToolCall(
            timestamp=self.clock(),
            tool=tool,
            args=copy.deepcopy(args),
            result=copy.deepcopy(result),
            alias=alias if alias is not None else self.alias,
        )
        self._calls.append(call)
        return call

    @property
    def calls(self) -> list[ToolCall]:
        return list(self._calls)

    def calls_to(self, tool: str) -> list[ToolCall]:
        return [c for c in self._calls if c.tool == tool]

    def to_list(self) -> list[dict[str, Any]]:
        return [c.to_dict() for c in self._calls]
