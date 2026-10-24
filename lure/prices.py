"""Model prices from a prices file (USD per million tokens).

Lure ships no rates: `lure compare --prices` and `lure run --prices` read a
file like prices.example.yaml, and every cost is an estimate from the token
counts each model call reports.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml


def model_name(target: str) -> str:
    """'anthropic:claude-haiku-5-5' -> 'claude-haiku-5-5'."""
    return target.split(":", 1)[1] if ":" in target else target


# Usage keys as the adapters record them, and the price field for each.
PRICE_FIELDS = {
    "input_tokens": "input",
    "output_tokens": "output",
    "cache_creation_input_tokens": "cache_write",
    "cache_read_input_tokens": "cache_read",
}
INPUT_KEYS = ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")


class PricesError(ValueError):
    """The prices file is missing, malformed or has a bad rate."""


@dataclass(frozen=True)
class Prices:
    """USD per million tokens, by model name, from a prices file."""

    source: str
    models: dict[str, dict[str, float]]
    as_of: str | None = None

    def rates(self, model: str) -> dict[str, float] | None:
        """Rates for 'anthropic:claude-x' or 'claude-x', whichever way the
        prices file names it; an exact match wins. Only a provider prefix is
        dropped, never a tag: 'ollama:llama3.1:8b' matches 'llama3.1:8b'."""
        if model in self.models:
            return self.models[model]
        if model_name(model) in self.models:
            return self.models[model_name(model)]
        return next((r for name, r in self.models.items() if model_name(name) == model), None)

    def cost(self, model: str, usage: dict[str, int]) -> float | None:
        """Dollars for this usage, or None if a needed rate is missing."""
        rates = self.rates(model)
        if rates is None:
            return None
        total = 0.0
        for key, n in usage.items():
            if not n:
                continue
            rate = rates.get(PRICE_FIELDS.get(key, ""))
            if rate is None:
                return None
            total += n * rate / 1_000_000
        return total


def load_prices(path: str | Path) -> Prices:
    path = Path(path)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise PricesError(f"prices file not found: {path}") from None
    except yaml.YAMLError as e:
        raise PricesError(f"{path}: not valid YAML: {e}") from None
    if not isinstance(data, dict) or not isinstance(data.get("models"), dict) or not data["models"]:
        raise PricesError(f"{path}: needs a 'models' mapping of model name to rates")
    models: dict[str, dict[str, float]] = {}
    for name, rates in data["models"].items():
        if not isinstance(rates, dict):
            raise PricesError(f"{path}: {name}: rates must be a mapping")
        unknown = set(rates) - set(PRICE_FIELDS.values())
        if unknown:
            raise PricesError(f"{path}: {name}: unknown rate {', '.join(sorted(unknown))}; "
                              f"use {', '.join(PRICE_FIELDS.values())}")
        for need in ("input", "output"):
            if need not in rates:
                raise PricesError(f"{path}: {name}: missing {need}")
        for k, v in rates.items():
            if isinstance(v, bool) or not isinstance(v, (int, float)) or v < 0:
                raise PricesError(f"{path}: {name}: {k} must be a number of at least 0")
        models[str(name)] = {k: float(v) for k, v in rates.items()}
    as_of = data.get("as_of")
    return Prices(str(path), models, str(as_of) if as_of is not None else None)
