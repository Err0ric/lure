import json

import httpx2
import pytest

from lure.adapters import AdapterError, ToolResult, ToolSpec
from lure.adapters.anthropic import AnthropicAdapter
from lure.adapters.ollama import OllamaAdapter

READ_INBOX = ToolSpec(
    name="read_inbox",
    description="Read the user's inbox.",
    parameters={"type": "object", "properties": {"limit": {"type": "integer"}}},
)


class Recorder:
    """MockTransport handler that returns canned responses and keeps requests."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests = []

    def __call__(self, request):
        self.requests.append(request)
        status, body = self.responses.pop(0)
        if isinstance(body, str):
            return httpx2.Response(status, text=body)
        return httpx2.Response(status, json=body)

    def body(self, i):
        return json.loads(self.requests[i].content)


# Ollama


def ollama_reply(content="", tool_calls=None, done_reason="stop"):
    message = {"role": "assistant", "content": content}
    if tool_calls:
        message["tool_calls"] = tool_calls
    return {"model": "llama3.1:8b", "message": message, "done": True, "done_reason": done_reason}


def make_ollama(*responses, **kwargs):
    rec = Recorder(*responses)
    adapter = OllamaAdapter(transport=httpx2.MockTransport(rec), **kwargs)
    return adapter, rec


def test_ollama_defaults():
    adapter, _ = make_ollama()
    assert adapter.base_url == "http://localhost:11434"
    assert adapter.target_name == "ollama:llama3.1:8b"


def test_ollama_sends_task_and_tools():
    adapter, rec = make_ollama((200, ollama_reply("Nothing new.")))
    turn = adapter.start("You are an assistant.", [READ_INBOX]).send_task("Check mail.")

    req = rec.requests[0]
    assert req.method == "POST"
    assert str(req.url) == "http://localhost:11434/api/chat"
    body = rec.body(0)
    assert body["model"] == "llama3.1:8b"
    assert body["stream"] is False
    assert body["messages"] == [
        {"role": "system", "content": "You are an assistant."},
        {"role": "user", "content": "Check mail."},
    ]
    assert body["tools"] == [
        {
            "type": "function",
            "function": {
                "name": "read_inbox",
                "description": "Read the user's inbox.",
                "parameters": READ_INBOX.parameters,
            },
        }
    ]
    assert turn.text == "Nothing new."
    assert not turn.wants_tools
    assert turn.stop_reason == "stop"


def test_ollama_records_token_counts():
    reply = {**ollama_reply("hi"), "prompt_eval_count": 812, "eval_count": 96}
    adapter, _ = make_ollama((200, reply))
    turn = adapter.start("s", []).send_task("t")
    assert turn.usage == {"input_tokens": 812, "output_tokens": 96}


def test_ollama_missing_token_counts_are_left_out():
    adapter, _ = make_ollama((200, {**ollama_reply("hi"), "eval_count": 7}))
    assert adapter.start("s", []).send_task("t").usage == {"output_tokens": 7}
    adapter, _ = make_ollama((200, ollama_reply("hi")))
    assert adapter.start("s", []).send_task("t").usage == {}


def test_ollama_custom_model_and_url():
    adapter, rec = make_ollama(
        (200, ollama_reply("hi")), model="qwen3:8b", base_url="http://gpu-box:11434"
    )
    adapter.start("s", []).send_task("t")
    assert str(rec.requests[0].url) == "http://gpu-box:11434/api/chat"
    assert rec.body(0)["model"] == "qwen3:8b"


def test_ollama_parses_tool_calls():
    adapter, _ = make_ollama(
        (200, ollama_reply(tool_calls=[
            {"function": {"name": "read_inbox", "arguments": {"limit": 3}}},
            {"function": {"name": "read_inbox", "arguments": '{"limit": 1}'}},
        ]))
    )
    turn = adapter.start("s", [READ_INBOX]).send_task("t")
    assert turn.wants_tools
    assert [(c.id, c.name, c.arguments) for c in turn.tool_calls] == [
        ("call_1", "read_inbox", {"limit": 3}),
        ("call_2", "read_inbox", {"limit": 1}),
    ]


def test_ollama_tool_results_round_trip():
    first = ollama_reply(tool_calls=[{"function": {"name": "read_inbox", "arguments": {}}}])
    adapter, rec = make_ollama((200, first), (200, ollama_reply("Two emails.")))
    convo = adapter.start("s", [READ_INBOX])
    turn = convo.send_task("t")
    final = convo.send_tool_results(
        [ToolResult(call_id=turn.tool_calls[0].id, name="read_inbox", content="[]")]
    )
    messages = rec.body(1)["messages"]
    assert messages[2] == first["message"]
    assert messages[3] == {"role": "tool", "content": "[]", "tool_name": "read_inbox"}
    assert final.text == "Two emails."


def test_ollama_error_result_is_marked():
    first = ollama_reply(tool_calls=[{"function": {"name": "read_inbox", "arguments": {}}}])
    adapter, rec = make_ollama((200, first), (200, ollama_reply("ok")))
    convo = adapter.start("s", [READ_INBOX])
    convo.send_task("t")
    convo.send_tool_results([ToolResult("call_1", "read_inbox", "boom", is_error=True)])
    assert rec.body(1)["messages"][-1]["content"] == "ERROR: boom"


@pytest.mark.parametrize(
    "response, match",
    [
        ((404, '{"error": "model not found"}'), "HTTP 404"),
        ((200, "not json"), "invalid JSON"),
        ((200, {"done": True}), "no message"),
    ],
)
def test_ollama_bad_responses_raise(response, match):
    adapter, _ = make_ollama(response)
    with pytest.raises(AdapterError, match=match):
        adapter.start("s", []).send_task("t")


def test_ollama_connection_error_raises():
    def refuse(request):
        raise httpx2.ConnectError("connection refused", request=request)

    adapter = OllamaAdapter(transport=httpx2.MockTransport(refuse))
    with pytest.raises(AdapterError, match="failed"):
        adapter.start("s", []).send_task("t")


# Anthropic


def anthropic_reply(content, stop_reason="end_turn"):
    return {
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "model": "claude-haiku-5-5",
        "content": content,
        "stop_reason": stop_reason,
        "stop_sequence": None,
        "usage": {"input_tokens": 10, "output_tokens": 5},
    }


THINKING = {"type": "thinking", "thinking": "", "signature": "sig-abc"}
TOOL_USE = {"type": "tool_use", "id": "toolu_1", "name": "read_inbox", "input": {"limit": 2}}


def make_anthropic(*responses, **kwargs):
    rec = Recorder(*responses)
    kwargs.setdefault("api_key", "test-key")
    adapter = AnthropicAdapter(
        transport=httpx2.MockTransport(rec), max_retries=0, **kwargs
    )
    return adapter, rec


def test_anthropic_defaults():
    adapter, _ = make_anthropic()
    assert adapter.target_name == "anthropic:claude-haiku-5-5"
    assert adapter.effort == "medium"


def test_anthropic_omits_empty_tools():
    # The LLM judge opens a conversation with no tools.
    adapter, rec = make_anthropic(
        (200, anthropic_reply([{"type": "text", "text": "{}"}]))
    )
    adapter.start("Rubric.", []).send_task("Classify.")
    assert "tools" not in rec.body(0)


def test_ollama_omits_empty_tools():
    adapter, rec = make_ollama((200, ollama_reply("{}")))
    adapter.start("Rubric.", []).send_task("Classify.")
    assert "tools" not in rec.body(0)


def test_anthropic_sends_task_and_tools():
    adapter, rec = make_anthropic(
        (200, anthropic_reply([{"type": "text", "text": "All quiet."}]))
    )
    turn = adapter.start("You are an assistant.", [READ_INBOX]).send_task("Check mail.")

    req = rec.requests[0]
    assert str(req.url) == "https://api.anthropic.com/v1/messages"
    assert req.headers["authorization"] == "Bearer test-key"
    body = rec.body(0)
    assert body["model"] == "claude-haiku-5-5"
    assert body["system"] == "You are an assistant."
    assert body["messages"] == [{"role": "user", "content": "Check mail."}]
    assert body["tools"] == [
        {
            "name": "read_inbox",
            "description": "Read the user's inbox.",
            "input_schema": READ_INBOX.parameters,
        }
    ]
    assert body["output_config"] == {"effort": "medium"}
    assert "fallbacks" not in body
    assert turn.text == "All quiet."
    assert turn.stop_reason == "end_turn"


def test_anthropic_custom_model_and_effort():
    adapter, rec = make_anthropic(
        (200, anthropic_reply([{"type": "text", "text": "hi"}])),
        model="claude-sonnet-5-5",
        effort="low",
    )
    adapter.start("s", []).send_task("t")
    assert rec.body(0)["model"] == "claude-sonnet-5-5"
    assert rec.body(0)["output_config"] == {"effort": "low"}


def test_anthropic_effort_none_uses_model_default():
    adapter, rec = make_anthropic(
        (200, anthropic_reply([{"type": "text", "text": "hi"}])), effort=None
    )
    adapter.start("s", []).send_task("t")
    assert "output_config" not in rec.body(0)


def test_anthropic_parses_tool_calls_and_skips_thinking():
    adapter, _ = make_anthropic(
        (200, anthropic_reply(
            [THINKING, {"type": "text", "text": "Checking."}, TOOL_USE], "tool_use"
        ))
    )
    turn = adapter.start("s", [READ_INBOX]).send_task("t")
    assert turn.text == "Checking."
    assert turn.stop_reason == "tool_use"
    assert [(c.id, c.name, c.arguments) for c in turn.tool_calls] == [
        ("toolu_1", "read_inbox", {"limit": 2})
    ]


def test_anthropic_reports_token_usage():
    reply = anthropic_reply([{"type": "text", "text": "ok"}])
    reply["usage"] = {"input_tokens": 120, "output_tokens": 40,
                      "cache_read_input_tokens": 0, "cache_creation_input_tokens": None}
    adapter, _ = make_anthropic((200, reply))
    turn = adapter.start("s", []).send_task("t")
    # Missing or null counts are left out rather than guessed.
    assert turn.usage == {"input_tokens": 120, "output_tokens": 40, "cache_read_input_tokens": 0}


def test_anthropic_tool_results_replay_full_content():
    adapter, rec = make_anthropic(
        (200, anthropic_reply([THINKING, TOOL_USE], "tool_use")),
        (200, anthropic_reply([{"type": "text", "text": "Done."}])),
    )
    convo = adapter.start("s", [READ_INBOX])
    convo.send_task("t")
    final = convo.send_tool_results(
        [ToolResult(call_id="toolu_1", name="read_inbox", content="[]")]
    )
    messages = rec.body(1)["messages"]
    assert messages[1] == {"role": "assistant", "content": [THINKING, TOOL_USE]}
    assert messages[2] == {
        "role": "user",
        "content": [
            {"type": "tool_result", "tool_use_id": "toolu_1", "content": "[]", "is_error": False}
        ],
    }
    assert final.text == "Done."


def test_anthropic_refusal_is_reported_not_raised():
    adapter, _ = make_anthropic((200, anthropic_reply([], "refusal")))
    turn = adapter.start("s", []).send_task("t")
    assert turn.stop_reason == "refusal"
    assert turn.text == ""
    assert not turn.wants_tools


@pytest.mark.parametrize("status", [400, 401, 429, 500])
def test_anthropic_http_errors_raise(status):
    error = {"type": "error", "error": {"type": "api_error", "message": "nope"}}
    adapter, _ = make_anthropic((status, error))
    with pytest.raises(AdapterError, match=f"HTTP {status}"):
        adapter.start("s", []).send_task("t")


def test_anthropic_key_loaded_from_dotenv(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "placeholder")
    monkeypatch.delenv("ANTHROPIC_API_KEY")
    (tmp_path / ".env").write_text("ANTHROPIC_API_KEY=from-dotenv\n")
    monkeypatch.chdir(tmp_path)
    adapter, rec = make_anthropic(
        (200, anthropic_reply([{"type": "text", "text": "hi"}])), api_key=None
    )
    adapter.start("s", []).send_task("t")
    assert rec.requests[0].headers["authorization"] == "Bearer from-dotenv"


# Tool updates mid-conversation (rug pull)


CHANGED = ToolSpec(name="read_inbox", description="Read the inbox. Changed.",
                   parameters=READ_INBOX.parameters)


def test_anthropic_set_tools_changes_the_next_request():
    adapter, rec = make_anthropic(
        (200, anthropic_reply([TOOL_USE], "tool_use")),
        (200, anthropic_reply([{"type": "text", "text": "Done."}])),
    )
    convo = adapter.start("s", [READ_INBOX])
    convo.send_task("t")
    convo.set_tools([CHANGED])
    convo.send_tool_results([ToolResult("toolu_1", "read_inbox", "[]")])
    assert rec.body(0)["tools"][0]["description"] == "Read the user's inbox."
    assert rec.body(1)["tools"][0]["description"] == "Read the inbox. Changed."


def test_ollama_set_tools_changes_the_next_request():
    adapter, rec = make_ollama((200, ollama_reply("a")), (200, ollama_reply("b")))
    convo = adapter.start("s", [READ_INBOX])
    convo.send_task("t")
    convo.set_tools([CHANGED])
    convo.send_task("t2")
    assert rec.body(0)["tools"][0]["function"]["description"] == "Read the user's inbox."
    assert rec.body(1)["tools"][0]["function"]["description"] == "Read the inbox. Changed."


def test_conversation_without_set_tools_raises_adapter_error():
    from lure.adapters.base import Conversation

    class Fixed(Conversation):
        def send_task(self, task):
            raise NotImplementedError

        def send_tool_results(self, results):
            raise NotImplementedError

    with pytest.raises(AdapterError, match="cannot change tools"):
        Fixed().set_tools([READ_INBOX])


# Output schema (the LLM judge)

SCHEMA = {"type": "object", "properties": {"label": {"type": "string"}},
          "required": ["label"], "additionalProperties": False}


def test_anthropic_output_schema_merges_with_effort():
    adapter, rec = make_anthropic((200, anthropic_reply([{"type": "text", "text": "{}"}])))
    convo = adapter.start("s", [])
    assert convo.structured is False
    convo.set_output_schema(SCHEMA)
    convo.send_task("t")
    assert rec.body(0)["output_config"] == {
        "effort": "medium", "format": {"type": "json_schema", "schema": SCHEMA}}
    assert convo.structured is True


def test_anthropic_output_schema_without_effort():
    adapter, rec = make_anthropic((200, anthropic_reply([{"type": "text", "text": "{}"}])),
                                  effort=None)
    convo = adapter.start("s", [])
    convo.set_output_schema(SCHEMA)
    convo.send_task("t")
    assert rec.body(0)["output_config"] == {"format": {"type": "json_schema", "schema": SCHEMA}}


def test_anthropic_target_requests_carry_no_format():
    adapter, rec = make_anthropic((200, anthropic_reply([{"type": "text", "text": "Hi"}])))
    convo = adapter.start("s", [READ_INBOX])
    convo.send_task("t")
    assert rec.body(0)["output_config"] == {"effort": "medium"}
    assert convo.structured is False


def test_ollama_output_schema_is_sent_as_format():
    adapter, rec = make_ollama((200, ollama_reply("{}")), (200, ollama_reply("Hi")))
    convo = adapter.start("s", [])
    convo.set_output_schema(SCHEMA)
    convo.send_task("t")
    assert rec.body(0)["format"] == SCHEMA and convo.structured is True
    adapter.start("s", [READ_INBOX]).send_task("t")
    assert "format" not in rec.body(1)
