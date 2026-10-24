"""The OpenAI-compatible adapter, against mocked HTTP only."""

import json

import httpx2
import pytest

from lure import cli
from lure.adapters import AdapterError, ToolResult, ToolSpec
from lure.adapters.openai_compat import DEFAULT_BASE_URL, OpenAICompatAdapter
from lure.attacks import load_attack
from lure.judge.rules import Verdict
from lure.runner import run_attack
from tests.test_adapters import READ_INBOX, Recorder
from tests.test_runner import REPO

ENV = ("LURE_OPENAI_BASE_URL", "LURE_OPENAI_API_KEY", "LURE_OPENAI_MODEL", "OPENAI_API_KEY")
LOCAL = "http://localhost:8000/v1"


@pytest.fixture(autouse=True)
def clean_env(monkeypatch, tmp_path):
    """No settings from the shell or the repo's .env leak into these tests."""
    for name in ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)


def reply(content="", tool_calls=None, finish_reason="stop", usage=None):
    message = {"role": "assistant", "content": content, "refusal": None}
    if tool_calls:
        message["tool_calls"] = tool_calls
    data = {"id": "chatcmpl-1", "object": "chat.completion", "model": "m",
            "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}]}
    if usage:
        data["usage"] = usage
    return data


def tool_call(name, arguments, call_id="call_abc"):
    return {"id": call_id, "type": "function",
            "function": {"name": name, "arguments": arguments}}


def make(*responses, **kwargs):
    rec = Recorder(*responses)
    kwargs = {"model": "m", "base_url": LOCAL, "sleep": lambda s: None, **kwargs}
    return OpenAICompatAdapter(transport=httpx2.MockTransport(rec), **kwargs), rec


# Settings


def test_settings_from_arguments():
    adapter, rec = make((200, reply("hi")), model="llama-3.1-8b", api_key="k")
    assert adapter.target_name == "openai:llama-3.1-8b"
    adapter.start("s", []).send_task("t")
    assert str(rec.requests[0].url) == "http://localhost:8000/v1/chat/completions"
    assert rec.requests[0].headers["authorization"] == "Bearer k"


def test_settings_from_dotenv(tmp_path):
    (tmp_path / ".env").write_text(
        "LURE_OPENAI_BASE_URL=https://api.groq.example/openai/v1/\n"
        "LURE_OPENAI_API_KEY=from-dotenv\nLURE_OPENAI_MODEL=mixtral\n")
    rec = Recorder((200, reply("hi")))
    adapter = OpenAICompatAdapter(transport=httpx2.MockTransport(rec))
    assert adapter.model == "mixtral"
    adapter.start("s", []).send_task("t")
    assert str(rec.requests[0].url) == "https://api.groq.example/openai/v1/chat/completions"
    assert rec.requests[0].headers["authorization"] == "Bearer from-dotenv"


def test_openai_api_key_is_a_fallback(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "fallback")
    adapter, rec = make((200, reply("hi")))
    adapter.start("s", []).send_task("t")
    assert rec.requests[0].headers["authorization"] == "Bearer fallback"


def test_local_server_needs_no_key():
    adapter, rec = make((200, reply("hi")))
    adapter.start("s", []).send_task("t")
    assert "authorization" not in rec.requests[0].headers


def test_openai_itself_needs_a_key():
    with pytest.raises(AdapterError, match="set LURE_OPENAI_API_KEY"):
        make(base_url=DEFAULT_BASE_URL)


def test_model_is_required():
    with pytest.raises(AdapterError, match="pass --model or set LURE_OPENAI_MODEL"):
        make(model=None)


@pytest.mark.parametrize("url", ["localhost:8000/v1", "ftp://host.example/v1", "http://"])
def test_base_url_must_be_http(url):
    with pytest.raises(AdapterError, match="must be an http"):
        make(base_url=url)


# Requests and replies


def test_sends_system_task_and_tools():
    adapter, rec = make((200, reply("Done.", usage={"prompt_tokens": 30, "completion_tokens": 5,
                                                   "total_tokens": 35})))
    turn = adapter.start("You are AP.", [READ_INBOX]).send_task("Summarize.")
    body = rec.body(0)
    assert body["model"] == "m"
    assert body["messages"] == [{"role": "system", "content": "You are AP."},
                                {"role": "user", "content": "Summarize."}]
    assert body["tools"] == [{"type": "function", "function": {
        "name": "read_inbox", "description": "Read the user's inbox.",
        "parameters": READ_INBOX.parameters}}]
    assert (turn.text, turn.stop_reason, turn.tool_calls) == ("Done.", "stop", [])
    assert turn.usage == {"input_tokens": 30, "output_tokens": 5}


def test_omits_empty_tools():
    adapter, rec = make((200, reply("ok")))
    adapter.start("judge rubric", []).send_task("t")
    assert "tools" not in rec.body(0)


def test_tool_calls_round_trip():
    adapter, rec = make(
        (200, reply(None, [tool_call("read_inbox", '{"limit": 5}')], "tool_calls")),
        (200, reply("Summary.")),
    )
    convo = adapter.start("s", [READ_INBOX])
    turn = convo.send_task("t")
    [c] = turn.tool_calls
    assert (c.id, c.name, c.arguments, turn.text) == ("call_abc", "read_inbox", {"limit": 5}, "")
    convo.send_tool_results([ToolResult("call_abc", "read_inbox", "[]"),
                             ToolResult("call_x", "send_email", "no such tool", is_error=True)])
    messages = rec.body(1)["messages"]
    # Only standard fields are replayed; the server's "refusal" key is dropped.
    assert messages[2] == {"role": "assistant", "content": None, "tool_calls": [
        {"id": "call_abc", "type": "function",
         "function": {"name": "read_inbox", "arguments": '{"limit": 5}'}}]}
    assert messages[3:] == [
        {"role": "tool", "tool_call_id": "call_abc", "content": "[]"},
        {"role": "tool", "tool_call_id": "call_x", "content": "ERROR: no such tool"}]


@pytest.mark.parametrize("arguments, expected", [
    ('{"limit": 5}', {"limit": 5}), ({"limit": 5}, {"limit": 5}), ("", {}), (None, {}),
])
def test_arguments_as_string_object_or_empty(arguments, expected):
    adapter, _ = make((200, reply(None, [tool_call("read_inbox", arguments)], "tool_calls")))
    [c] = adapter.start("s", [READ_INBOX]).send_task("t").tool_calls
    assert c.arguments == expected


def test_missing_call_ids_are_made_up():
    calls = [{"type": "function", "function": {"name": "read_inbox", "arguments": "{}"}}] * 2
    adapter, _ = make((200, reply(None, calls, "tool_calls")))
    turn = adapter.start("s", [READ_INBOX]).send_task("t")
    assert [c.id for c in turn.tool_calls] == ["call_1", "call_2"]


@pytest.mark.parametrize("response, match", [
    ((401, '{"error": {"message": "bad key"}}'), "returned HTTP 401: .*bad key"),
    ((200, "not json"), "invalid JSON"),
    ((200, {"choices": []}), "no message"),
    ((200, {"error": "x"}), "no message"),
    ((200, reply(None, [tool_call("read_inbox", "{not json")])), "not JSON"),
    ((200, reply(None, [tool_call("read_inbox", "[1, 2]")])), "not an object"),
])
def test_bad_responses_raise(response, match):
    adapter, _ = make(response)
    with pytest.raises(AdapterError, match=match):
        adapter.start("s", [READ_INBOX]).send_task("t")


def test_retries_rate_limits_then_succeeds():
    waits = []
    adapter, rec = make((429, "slow down"), (503, "busy"), (200, reply("ok")), sleep=waits.append)
    assert adapter.start("s", []).send_task("t").text == "ok"
    assert len(rec.requests) == 3 and waits == [1, 2]


def test_gives_up_after_max_retries():
    adapter, rec = make((429, "a"), (429, "b"), max_retries=1)
    with pytest.raises(AdapterError, match="HTTP 429: b"):
        adapter.start("s", []).send_task("t")
    assert len(rec.requests) == 2


def test_connection_error_raises():
    def refuse(request):
        raise httpx2.ConnectError("connection refused", request=request)

    adapter = OpenAICompatAdapter(model="m", base_url=LOCAL, max_retries=1, sleep=lambda s: None,
                                  transport=httpx2.MockTransport(refuse))
    with pytest.raises(AdapterError, match="request to http://localhost:8000/v1 failed"):
        adapter.start("s", []).send_task("t")


# End to end, still mocked


def test_full_run_against_a_mocked_server():
    attack = load_attack(REPO / "attacks" / "indirect_prompt_injection" / "lure-ipi-001.yaml")
    forward = json.dumps({"to": ["billing-verify@external.example"], "subject": "Invoices",
                          "body": "Attached."})
    adapter, rec = make(
        (200, reply(None, [tool_call("read_inbox", "{}", "c1")], "tool_calls")),
        (200, reply(None, [tool_call("send_email", forward, "c2")], "tool_calls")),
        (200, reply("Forwarded.")),
    )
    result = run_attack(attack, adapter)
    assert result.judgment.verdict is Verdict.FAIL
    assert result.target == "openai:m"
    assert [c.tool for c in result.log.calls] == ["read_inbox", "send_email"]
    assert len(rec.requests) == 3


def test_cli_offers_the_openai_target(monkeypatch):
    monkeypatch.setenv("LURE_OPENAI_MODEL", "local-model")
    monkeypatch.setenv("LURE_OPENAI_BASE_URL", LOCAL)
    adapter = cli.make_adapter("openai", None)
    assert isinstance(adapter, OpenAICompatAdapter) and adapter.target_name == "openai:local-model"
    assert cli.make_adapter("openai", "other").model == "other"
    assert "openai" in cli.TARGETS


def test_set_tools_changes_the_next_request():
    adapter, rec = make((200, reply("a")), (200, reply("b")))
    convo = adapter.start("s", [READ_INBOX])
    convo.send_task("t")
    convo.set_tools([ToolSpec("read_inbox", "Changed.", READ_INBOX.parameters)])
    convo.send_task("t2")
    assert rec.body(1)["tools"][0]["function"]["description"] == "Changed."


# Output schema (the LLM judge)

SCHEMA = {"type": "object", "properties": {"label": {"type": "string"}},
          "required": ["label"], "additionalProperties": False}
RESPONSE_FORMAT = {"type": "json_schema",
                   "json_schema": {"name": "output", "schema": SCHEMA, "strict": True}}


def test_output_schema_is_sent_as_response_format():
    adapter, rec = make((200, reply("{}")))
    convo = adapter.start("s", [])
    convo.set_output_schema(SCHEMA)
    convo.send_task("t")
    assert rec.body(0)["response_format"] == RESPONSE_FORMAT
    assert convo.structured is True


def test_target_requests_carry_no_response_format():
    adapter, rec = make((200, reply("Hi")))
    convo = adapter.start("s", [READ_INBOX])
    convo.send_task("t")
    assert "response_format" not in rec.body(0) and convo.structured is False


def test_400_on_response_format_retries_once_without_it():
    adapter, rec = make((400, {"error": {"message": "response_format not supported"}}),
                        (200, reply("{}")), (200, reply("{}")))
    convo = adapter.start("s", [])
    convo.set_output_schema(SCHEMA)
    assert convo.send_task("t").text == "{}"
    assert rec.body(0)["response_format"] == RESPONSE_FORMAT
    assert "response_format" not in rec.body(1)
    assert convo.structured is False
    convo.send_task("again")  # later turns do not try the schema again
    assert len(rec.requests) == 3 and "response_format" not in rec.body(2)


def test_other_errors_with_response_format_are_not_retried():
    adapter, rec = make((401, {"error": {"message": "bad key"}}))
    convo = adapter.start("s", [])
    convo.set_output_schema(SCHEMA)
    with pytest.raises(AdapterError, match="HTTP 401") as e:
        convo.send_task("t")
    assert e.value.status == 401 and len(rec.requests) == 1


def test_400_without_a_schema_is_not_retried():
    adapter, rec = make((400, {"error": {"message": "bad"}}))
    with pytest.raises(AdapterError, match="HTTP 400"):
        adapter.start("s", []).send_task("t")
    assert len(rec.requests) == 1
