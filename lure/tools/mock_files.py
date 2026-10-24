"""Mock file tools: list_files, read_file, write_file and delete_file.

Safety: this module never touches the real filesystem. The files come from
a JSON fixture and live in an in-memory dict for the run; writes and
deletes change only that dict. Every call is recorded in the shared
ToolCallLog, with its return value, for the Judge.
"""

from __future__ import annotations

import copy
from typing import Any

from lure.tools.args import ToolError, as_path, as_text, normalize_path
from lure.tools.call_log import ToolCallLog
from lure.tools.mock_email import FixtureError

REQUIRED_FIELDS = ("path", "content")


def check_files(files: Any) -> None:
    """A files fixture is a JSON list of {path, content} with unique paths."""
    if not isinstance(files, list):
        raise FixtureError("files fixture must be a JSON list")
    seen = set()
    for i, f in enumerate(files):
        if not isinstance(f, dict):
            raise FixtureError(f"files[{i}] must be an object")
        missing = [k for k in REQUIRED_FIELDS if k not in f]
        if missing:
            raise FixtureError(f"files[{i}] missing fields {missing}")
        if not all(isinstance(f[k], str) for k in REQUIRED_FIELDS):
            raise FixtureError(f"files[{i}] path and content must be strings")
        path = normalize_path(f["path"])
        if path in seen:
            raise FixtureError(f"files[{i}] duplicates path {path!r}")
        seen.add(path)


class MockFiles:
    """In-memory file share exposing the file tools to a target."""

    def __init__(self, files: list[dict[str, Any]], log: ToolCallLog) -> None:
        check_files(files)
        self._files = {normalize_path(f["path"]): f["content"] for f in files}
        self.log = log

    @property
    def files(self) -> dict[str, str]:
        """The share as it stands now, after any writes and deletes."""
        return dict(self._files)

    def put(self, path: str, content: str) -> None:
        """A file appears or changes (a responder). Not a tool, so not logged."""
        self._files[normalize_path(path)] = content

    def list_files(self, prefix: str | None = None) -> list[str]:
        """Return file paths in sorted order, optionally under a folder."""
        if prefix is not None:
            prefix = as_path("prefix", prefix)
        root = None if prefix in (None, "/") else prefix.rstrip("/") + "/"
        paths = sorted(p for p in self._files if root is None or p.startswith(root))
        self.log.record("list_files", {"prefix": prefix}, paths)
        return paths

    def read_file(self, path: str) -> dict[str, str]:
        path = as_path("path", path)
        if path not in self._files:
            raise ToolError(f"no file at {path}")
        result = {"path": path, "content": self._files[path]}
        self.log.record("read_file", {"path": path}, copy.deepcopy(result))
        return result

    def write_file(self, path: str, content: str) -> dict[str, Any]:
        """Create or overwrite a file in memory."""
        path = as_path("path", path)
        content = as_text("content", content)
        status = "overwritten" if path in self._files else "created"
        self._files[path] = content
        result = {"status": status, "path": path}
        self.log.record("write_file", {"path": path, "content": content}, result)
        return result

    def delete_file(self, path: str) -> dict[str, str]:
        """Remove a file from memory. Nothing on disk is touched."""
        path = as_path("path", path)
        if path not in self._files:
            raise ToolError(f"no file at {path}")
        del self._files[path]
        result = {"status": "deleted", "path": path}
        self.log.record("delete_file", {"path": path}, result)
        return result
