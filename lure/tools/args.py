"""Argument checks for mock tools.

Models often send loosely typed arguments ("10" for 10). Coerce what is
clearly meant, and reject the rest with a message the model can act on
instead of a Python exception string.
"""

from __future__ import annotations

import posixpath
import re
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Any

_INT_RE = re.compile(r"^[+-]?\d+$")
# "$4,812.50", "4812.5", "4,812.50 USD"
_AMOUNT_RE = re.compile(r"^\$?\s*([\d,]*\.?\d+)\s*(?:usd)?$", re.IGNORECASE)


class ToolError(ValueError):
    """A call the tool cannot complete. The message is shown to the model."""


class ToolArgumentError(ToolError):
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


def as_amount(name: str, value: Any) -> float:
    """Accept 4812.5, "4812.50", "$4,812.50" or "4,812.50 USD"; must be above 0.
    Returns the amount rounded to cents."""
    text = None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        text = str(value)
    elif isinstance(value, str):
        m = _AMOUNT_RE.match(value.strip())
        text = m.group(1).replace(",", "") if m else None
    try:
        amount = Decimal(text) if text is not None else None
    except InvalidOperation:
        amount = None
    if amount is None or not amount.is_finite():
        raise ToolArgumentError(f"{name} must be an amount like 1250.00, got {value!r}")
    if amount <= 0:
        raise ToolArgumentError(f"{name} must be more than 0, got {value!r}")
    return float(amount.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


def as_path(name: str, value: Any) -> str:
    """Accept "/shared/a.txt", "shared/a.txt" or "/shared/./a.txt"; return the
    normalized absolute form. Paths are keys into an in-memory fixture, never
    the real filesystem."""
    if not isinstance(value, str) or not value.strip():
        raise ToolArgumentError(f"{name} must be a file path like /shared/notes.txt")
    return normalize_path(value)


def normalize_path(path: str) -> str:
    path = posixpath.normpath("/" + path.strip().lstrip("/"))
    # normpath keeps a leading "//"; collapse it.
    return "/" + path.lstrip("/")
