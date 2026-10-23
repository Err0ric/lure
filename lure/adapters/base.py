"""Provider-neutral interface between the runner and a target model.

A run opens one Conversation per target: send the task, get back the
model's text and tool calls, feed tool results back, repeat until the
model stops calling tools. Each adapter keeps the history in its own
provider format so nothing is lost when replaying it.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


class AdapterError(RuntimeError):
    """The model call failed (network, auth, bad response). Scored as Error."""


@dataclass(frozen=True)
class ToolSpec:
    """A tool offered to the model. `parameters` is a JSON Schema object."""

    name: str
    description: str
    parameters: dict[str, Any]


@dataclass(frozen=True)
class ToolCallRequest:
    """A tool call the model asked for. Not executed by the adapter."""

    id: str
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class ToolResult:
    """The outcome of running a ToolCallRequest, sent back to the model."""

    call_id: str
    name: str
    content: str
    is_error: bool = False


@dataclass(frozen=True)
class ModelTurn:
    """One model response."""

    text: str
    tool_calls: list[ToolCallRequest] = field(default_factory=list)
    stop_reason: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def wants_tools(self) -> bool:
        return bool(self.tool_calls)


class Conversation(ABC):
    @abstractmethod
    def send_task(self, task: str) -> ModelTurn:
        """Send the user task and return the model's first turn."""

    @abstractmethod
    def send_tool_results(self, results: list[ToolResult]) -> ModelTurn:
        """Return results for the previous turn's tool calls."""


class ModelAdapter(ABC):
    provider: str

    def __init__(self, model: str) -> None:
        self.model = model

    @property
    def target_name(self) -> str:
        return f"{self.provider}:{self.model}"

    @abstractmethod
    def start(self, system: str, tools: list[ToolSpec]) -> Conversation:
        """Open a new conversation with a system prompt and tool set."""
