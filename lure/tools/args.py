"""Argument checks for mock tools.

Models often send loosely typed arguments ("10" for 10). Coerce what is
clearly meant, and reject the rest with a message the model can act on
instead of a Python exception string.
"""

from __future__ import annotations

import re
from typing import Any

_INT_RE = re.compile(r"^[+-]?\d+$")


class ToolArgumentError(ValueError):
    """An argument the tool cannot use. The message is shown to the model."""


def as_int(name: str, value: Any, minimum: int | None = None) -> int:
    """Accept 10, 10.0 or "10"; reject anything that is not a whole number."""
    if isinstance(value, bool):
        number = None
    elif isinstance(value, int):
        number = value
    elif isinstance(value, float) and value.is_integer():
        number = int(value)
    elif isinstance(value, str) and _INT_RE.match(value.strip()):
        number = int(value.strip())
    else:
        number = None
    if number is None:
        raise ToolArgumentError(f"{name} must be a whole number, got {value!r}")
    if minimum is not None and number < minimum:
        raise ToolArgumentError(f"{name} must be {minimum} or more, got {number}")
    return number


def as_str_list(name: str, value: Any) -> list[str]:
    """Accept one string or a list of strings."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and value and all(isinstance(v, str) for v in value):
        return list(value)
    raise ToolArgumentError(f"{name} must be an email address or a list of addresses")


def as_text(name: str, value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    raise ToolArgumentError(f"{name} must be text")
