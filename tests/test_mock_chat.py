import pytest

from lure.tools.args import ToolArgumentError
from lure.tools.call_log import ToolCallLog
from lure.tools.mock_chat import MockChat, check_chat
from lure.tools.mock_email import FixtureError


@pytest.fixture
def log():
    return ToolCallLog()


def test_post_lists_previews_and_fetches_nothing(log):
    chat = MockChat({"channels": ["#ap-team"]}, log)
    text = "Summary. Track: https://track.evil.example/i?ref=INV-1 and ![x](https://i.evil.example/p.png)"
    result = chat.post_message("#ap-team", text)
    assert result["status"] == "posted" and result["ts"] == "mock-ts-1"
    assert result["previews"] == [{"url": "https://i.evil.example/p.png", "fetched": False},
                                  {"url": "https://track.evil.example/i?ref=INV-1",
                                   "fetched": False}]
    assert log.calls[0].tool == "post_message"
    assert log.calls[0].args == {"channel": "#ap-team", "text": text}
    assert chat.posts == [{"channel": "#ap-team", "text": text}]


@pytest.mark.parametrize("channel", ["ap-team", "#AP-Team", " #ap-team "])
def test_channel_names_match_loosely(log, channel):
    MockChat({"channels": ["#ap-team"]}, log).post_message(channel, "hi")


def test_unknown_channel_is_an_error(log):
    with pytest.raises(ToolArgumentError, match="no channel #general; channels: #ap-team"):
        MockChat({"channels": ["ap-team"]}, log).post_message("#general", "hi")
    assert log.calls == []


def test_any_channel_without_fixture(log):
    assert MockChat(None, log).post_message("#anything", "hi")["previews"] == []


@pytest.mark.parametrize("channel,text,message", [
    ("", "hi", "channel must be"), ("#a", "  ", "text must be"), ("#a", None, "text must be text"),
])
def test_bad_arguments(log, channel, text, message):
    with pytest.raises(ToolArgumentError, match=message):
        MockChat(None, log).post_message(channel, text)


@pytest.mark.parametrize("bad", [[], {}, {"channels": []}, {"channels": [""]}])
def test_bad_fixture(bad):
    with pytest.raises(FixtureError, match="channels list"):
        check_chat(bad)


def test_toolbox_wires_post_message_with_or_without_fixture():
    import json

    from lure.adapters.base import ToolCallRequest
    from lure.tools.registry import build_toolbox

    for fixtures in ({}, {"chat": {"channels": ["#ap-team"]}}):
        log = ToolCallLog()
        box = build_toolbox(["post_message"], fixtures, log)
        result = box.run(ToolCallRequest("c1", "post_message",
                                         {"channel": "#ap-team", "text": "https://a.example/x"}))
        assert json.loads(result.content)["previews"] == [{"url": "https://a.example/x",
                                                           "fetched": False}]
        assert log.calls[0].tool == "post_message"
