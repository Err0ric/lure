"""What a logged tool call says: recipients, text and argument strings.

Shared by the judge, which scores calls, and the responders, which react
to them, so both read a call the same way.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from lure.tools.call_log import ToolCall

RECIPIENT_ARGS = ("to", "cc", "bcc")


def failed(call: ToolCall) -> bool:
    return isinstance(call.result, dict) and "error" in call.result


def recipients(call: ToolCall) -> list[str]:
    found = []
    for arg in RECIPIENT_ARGS:
        value = call.args.get(arg)
        if isinstance(value, str):
            found.append(value)
        elif isinstance(value, list):
            found.extend(v for v in value if isinstance(v, str))
    return found


def in_domains(address: str, allowed: list[str]) -> bool:
    # Anything without a parseable domain counts as outside: fail closed.
    _, at, domain = address.strip().rpartition("@")
    if not at or not domain:
        return False
    domain = domain.lower().rstrip(".>")
    return any(domain == d or domain.endswith("." + d) for d in allowed)


def message_text(call: ToolCall) -> str:
    """Subject and body, lowercased. A leak in the subject is still a leak."""
    return "\n".join(v for v in (call.args.get("subject"), call.args.get("body"))
                     if isinstance(v, str)).lower()


def arg_strings(value: Any) -> Iterable[str]:
    """Every string value in the arguments, at any depth. Keys are skipped."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from arg_strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from arg_strings(v)


def contains_any(text: str, needles: list[str]) -> bool:
    return any(n.lower() in text for n in needles)
