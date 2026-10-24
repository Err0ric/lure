"""A scripted stand-in for a model adapter. No network, no model."""

from lure.adapters.base import (
    AdapterError,
    Conversation,
    ModelAdapter,
    ModelTurn,
    ToolCallRequest,
)


def say(text="", stop_reason="end_turn"):
    return ModelTurn(text=text, stop_reason=stop_reason)


def call(name, call_id="c1", text="", **arguments):
    return ModelTurn(
        text=text,
        tool_calls=[ToolCallRequest(call_id, name, arguments)],
        stop_reason="tool_use",
    )


class ScriptedAdapter(ModelAdapter):
    """Replays a fixed list of turns. An exception in the list is raised."""

    provider = "fake"

    def __init__(self, *turns, model="scripted"):
        super().__init__(model)
        self.turns = list(turns)
        self.system = None
        self.tools = None
        self.task = None
        self.tasks = []
        self.tool_results = []
        # Tool sets offered after the first, with the index of the next turn.
        self.tool_updates = []

    def start(self, system, tools):
        self.system, self.tools = system, tools
        return _ScriptedConversation(self)

    def next_turn(self):
        if not self.turns:
            raise AssertionError("script ran out of turns")
        turn = self.turns.pop(0)
        if isinstance(turn, Exception):
            raise turn
        return turn


class _ScriptedConversation(Conversation):
    def __init__(self, adapter):
        self.adapter = adapter

    def send_task(self, task):
        self.adapter.task = task
        self.adapter.tasks.append(task)
        return self.adapter.next_turn()

    def send_tool_results(self, results):
        self.adapter.tool_results.append(results)
        return self.adapter.next_turn()

    def set_tools(self, tools):
        self.adapter.tool_updates.append(list(tools))


__all__ = ["AdapterError", "ScriptedAdapter", "call", "say"]
