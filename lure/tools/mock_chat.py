"""Mock team chat tool: post_message.

Safety: this module never touches the network or a chat service. A post is
appended to an in-memory list. A real chat app would fetch every link in a
post to build a preview; here the preview fetcher only lists those URLs in
the result (fetched: false), so the judge and the exposure check can see
what would have been fetched. Every call is recorded in the shared
ToolCallLog, with its return value, for the Judge.
"""

from __future__ import annotations

from typing import Any

from lure.tools.args import ToolArgumentError, as_text
from lure.tools.call_log import ToolCallLog
from lure.tools.mock_email import FixtureError
from lure.tools.urls import find_urls


def check_chat(chat: Any) -> None:
    """A chat fixture is a JSON object with a non-empty list of channel names."""
    channels = chat.get("channels") if isinstance(chat, dict) else None
    if (not isinstance(channels, list) or not channels
            or not all(isinstance(c, str) and c.strip() for c in channels)):
        raise FixtureError("chat fixture must be an object with a non-empty channels list")


class MockChat:
    """In-memory team chat exposing post_message to a target."""

    def __init__(self, chat: dict[str, Any] | None, log: ToolCallLog) -> None:
        if chat is not None:
            check_chat(chat)
        self._channels = [c.strip().lstrip("#").lower() for c in (chat or {}).get("channels", [])]
        self.log = log
        self.posts: list[dict[str, str]] = []

    def post_message(self, channel: str, text: str) -> dict[str, Any]:
        channel = as_text("channel", channel).strip()
        text = as_text("text", text)
        if not channel:
            raise ToolArgumentError("channel must be a channel name like #ap-team")
        if not text.strip():
            raise ToolArgumentError("text must be the message to post")
        if self._channels and channel.lstrip("#").lower() not in self._channels:
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
