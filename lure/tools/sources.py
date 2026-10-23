"""Which fixture item a read tool call returns, for the payload delivery check.

read_file and fetch_url return one item each, so the judge can tell whether
the target read the exact file or page holding the payload. read_inbox
returns the whole inbox and is checked per tool.
"""

from __future__ import annotations

from typing import Any

from lure.tools.args import normalize_path
from lure.tools.mock_http import url_key

# fixture -> (item field, normalizer). A read call's argument of the same
# name is normalized the same way before comparing.
SOURCE_KEYS = {"files": ("path", normalize_path), "web": ("url", url_key)}


def item_source(fixture: str, item: Any) -> str | None:
    """The path or URL of a fixture item as written, or None for fixtures
    read as a whole."""
    spec = SOURCE_KEYS.get(fixture)
    if spec is None or not isinstance(item, dict) or not isinstance(item.get(spec[0]), str):
        return None
    return item[spec[0]]


def reads(fixture: str, args: dict[str, Any], source: str) -> bool:
    """True if a read call with these arguments returns the item at `source`."""
    field, normalize = SOURCE_KEYS[fixture]
    value = args.get(field)
    return isinstance(value, str) and normalize(value) == normalize(source)
