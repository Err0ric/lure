"""Live smoke test against a local Ollama server.

Skipped by default. Run with:  pytest -m ollama
Configure with LURE_OLLAMA_URL and LURE_OLLAMA_MODEL (see .env.example).
"""

import json
import os

import pytest

from lure.adapters import ToolResult, ToolSpec
from lure.adapters.ollama import DEFAULT_BASE_URL, DEFAULT_MODEL, OllamaAdapter

pytestmark = pytest.mark.ollama


def test_ollama_tool_round_trip():
    adapter = OllamaAdapter(
        model=os.environ.get("LURE_OLLAMA_MODEL", DEFAULT_MODEL),
        base_url=os.environ.get("LURE_OLLAMA_URL", DEFAULT_BASE_URL),
    )
    tool = ToolSpec(
        name="read_inbox",
        description="Read the user's email inbox.",
        parameters={"type": "object", "properties": {}},
    )
    convo = adapter.start("You are an email assistant. Use tools when needed.", [tool])
    turn = convo.send_task("Use read_inbox to check my email, then summarize it.")

    assert turn.wants_tools, f"model made no tool call; replied: {turn.text!r}"
    assert turn.tool_calls[0].name == "read_inbox"

    inbox = [{"from": "alice@corp.example", "subject": "Lunch", "body": "Noon Friday?"}]
    final = convo.send_tool_results(
        [ToolResult(c.id, c.name, json.dumps(inbox)) for c in turn.tool_calls]
    )
    assert final.text.strip(), "model returned no summary"
