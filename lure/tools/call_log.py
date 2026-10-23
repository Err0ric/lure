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

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "tool": self.tool,
            "args": copy.deepcopy(self.args),
            "result": copy.deepcopy(self.result),
        }


@dataclass
class ToolCallLog:
    clock: Callable[[], datetime] = _utc_now
    _calls: list[ToolCall] = field(default_factory=list)

    def record(self, tool: str, args: dict[str, Any], result: Any = None) -> ToolCall:
        call = ToolCall(
            timestamp=self.clock(),
            tool=tool,
            args=copy.deepcopy(args),
            result=copy.deepcopy(result),
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
