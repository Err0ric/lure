"""Mock team chat tools: read_messages and post_message.

read_messages returns a channel's messages from the chat fixture, so a
payload can arrive through team chat (a shared channel with outside
guests, a bot, a teammate).

Safety: this module never touches the network or a chat service. A post is
appended to an in-memory list. A real chat app would fetch every link in a
post to build a preview; here the preview fetcher only lists those URLs in
the result (fetched: false), so the judge and the exposure check can see
what would have been fetched. Every call is recorded in the shared
ToolCallLog, with its return value, for the Judge.
"""

from __future__ import annotations

import copy
from typing import Any

from lure.tools.args import ToolArgumentError, as_int, as_text
from lure.tools.call_log import ToolCallLog
from lure.tools.mock_email import FixtureError
from lure.tools.urls import find_urls


def _name(channel: str) -> str:
    return channel.strip().lstrip("#").lower()


def check_chat(chat: Any) -> None:
    """A chat fixture is a JSON object with a non-empty list of channel names,
    and optionally messages: {channel, from, text} in those channels."""
    channels = chat.get("channels") if isinstance(chat, dict) else None
    if (not isinstance(channels, list) or not channels
            or not all(isinstance(c, str) and c.strip() for c in channels)):
        raise FixtureError("chat fixture must be an object with a non-empty channels list")
    if not set(chat) <= {"channels", "messages"}:
        raise FixtureError("chat fixture keys are channels and messages")
    messages = chat.get("messages", [])
    if not isinstance(messages, list):
        raise FixtureError("chat messages must be a list")
    names = {_name(c) for c in channels}
    for i, m in enumerate(messages):
        if not isinstance(m, dict) or set(m) != {"channel", "from", "text"} or not all(
                isinstance(m[k], str) and m[k].strip() for k in m):
            raise FixtureError(f"chat messages[{i}] must have channel, from and text")
        if _name(m["channel"]) not in names:
            raise FixtureError(f"chat messages[{i}] channel {m['channel']!r} is not in channels")


class MockChat:
    """In-memory team chat exposing post_message to a target."""

    def __init__(self, chat: dict[str, Any] | None, log: ToolCallLog) -> None:
        if chat is not None:
            check_chat(chat)
        self._channels = [_name(c) for c in (chat or {}).get("channels", [])]
        self._messages = copy.deepcopy((chat or {}).get("messages", []))
        self.log = log
        self.posts: list[dict[str, str]] = []

    def read_messages(self, channel: str, limit: int | None = None) -> list[dict[str, str]]:
        """A channel's messages, oldest first."""
        channel = as_text("channel", channel).strip()
        if _name(channel) not in self._channels:
            raise ToolArgumentError(f"no channel {channel}; channels: "
                                    + ", ".join("#" + c for c in self._channels))
        found = [m for m in self._messages if _name(m["channel"]) == _name(channel)]
        if limit is not None:
            found = found[-as_int("limit", limit, minimum=1):]
        result = copy.deepcopy(found)
        self.log.record("read_messages", {"channel": channel} | (
            {} if limit is None else {"limit": limit}), copy.deepcopy(result))
        return result

    def post_message(self, channel: str, text: str) -> dict[str, Any]:
        channel = as_text("channel", channel).strip()
        text = as_text("text", text)
        if not channel:
            raise ToolArgumentError("channel must be a channel name like #ap-team")
        if not text.strip():
            raise ToolArgumentError("text must be the message to post")
        if self._channels and _name(channel) not in self._channels:
            raise ToolArgumentError(
                f"no channel {channel}; channels: "
                + ", ".join("#" + c for c in self._channels))
        self.posts.append({"channel": channel, "text": text})
        # What a real client's link preview would fetch. Nothing is fetched.
        previews = [{"url": u.url, "fetched": False} for u in find_urls(text)]
        result = {"status": "posted", "channel": channel, "ts": f"mock-ts-{len(self.posts)}",
                  "previews": previews}
        self.log.record("post_message", {"channel": channel, "text": text}, result)
        return result
