"""Mock web tool: fetch_url.

Safety: this module never touches the network. Pages come from a JSON
fixture; a URL with no fixture page is an error, never a real request.
Every call is recorded in the shared ToolCallLog, with its return value,
for the Judge.
"""

from __future__ import annotations

import copy
import re
from typing import Any

from lure.tools.args import ToolArgumentError, ToolError
from lure.tools.call_log import ToolCallLog
from lure.tools.mock_email import FixtureError

REQUIRED_FIELDS = ("url", "title", "body")
_SCHEME_RE = re.compile(r"^https?://", re.IGNORECASE)


def url_key(url: str) -> str:
    """Match URLs loosely: scheme, host case, fragment and a trailing slash
    do not matter. The path and query do."""
    rest = _SCHEME_RE.sub("", url.strip()).split("#", 1)[0]
    host, slash, path = rest.partition("/")
    return host.lower() + (slash + path).rstrip("/")


def check_web(pages: Any) -> None:
    """A web fixture is a JSON list of {url, title, body} with unique URLs."""
    if not isinstance(pages, list):
        raise FixtureError("web fixture must be a JSON list")
    seen = set()
    for i, page in enumerate(pages):
        if not isinstance(page, dict):
            raise FixtureError(f"web[{i}] must be an object")
        missing = [k for k in REQUIRED_FIELDS if k not in page]
        if missing:
            raise FixtureError(f"web[{i}] missing fields {missing}")
        if not all(isinstance(page[k], str) for k in REQUIRED_FIELDS):
            raise FixtureError(f"web[{i}] url, title and body must be strings")
        if not _SCHEME_RE.match(page["url"]):
            raise FixtureError(f"web[{i}] url must start with http:// or https://")
        key = url_key(page["url"])
        if key in seen:
            raise FixtureError(f"web[{i}] duplicates url {page['url']!r}")
        seen.add(key)


class MockHttp:
    """Serves fixture pages to a target in place of the web."""

    def __init__(self, pages: list[dict[str, Any]], log: ToolCallLog) -> None:
        check_web(pages)
        self._pages = {url_key(p["url"]): copy.deepcopy(p) for p in pages}
        self.log = log

    def fetch_url(self, url: str) -> dict[str, Any]:
        if not isinstance(url, str) or not url.strip():
            raise ToolArgumentError("url must be a web address like https://site.example/page")
        page = self._pages.get(url_key(url))
        if page is None:
            raise ToolError(f"404 not found: {url.strip()}")
        result = {"url": page["url"], "status": 200, "title": page["title"],
                  "body": page["body"]}
        self.log.record("fetch_url", {"url": url.strip()}, copy.deepcopy(result))
        return result
