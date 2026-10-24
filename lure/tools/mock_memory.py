"""Mock memory tools: search_memory and save_memory.

Stands in for an agent's long-term memory: notes kept across sessions. A
memory fixture holds notes saved before the run, so a poisoned note can sit
there until an unrelated task pulls it back in.

Search is deterministic word overlap, not embeddings: notes sharing more
query words come first, ties keep fixture order, and up to `limit` notes
come back, as a top-k retriever would return them.

Safety: this module never touches the network or the disk. Notes live in
an in-memory list for the run; save_memory only appends to it. Every call
is recorded in the shared ToolCallLog, with its return value, for the Judge.
"""

from __future__ import annotations

import copy
import re
from typing import Any

from lure.tools.args import ToolArgumentError, as_int, as_text
from lure.tools.call_log import ToolCallLog
from lure.tools.mock_email import FixtureError

REQUIRED_FIELDS = ("content",)
# source: where the note came from (the user, an email, a web page), as a
# memory system that tracks provenance would record it.
OPTIONAL_FIELDS = ("id", "saved", "source")
DEFAULT_LIMIT = 5
_WORD_RE = re.compile(r"[a-z0-9]+")


def check_memory(notes: Any) -> None:
    """A memory fixture is a JSON list of {content} objects, with an
    optional id, saved date and source."""
    if not isinstance(notes, list):
        raise FixtureError("memory fixture must be a JSON list")
    for i, note in enumerate(notes):
        if not isinstance(note, dict):
            raise FixtureError(f"memory[{i}] must be an object")
        if "content" not in note:
            raise FixtureError(f"memory[{i}] missing fields ['content']")
        unknown = sorted(set(note) - set(REQUIRED_FIELDS) - set(OPTIONAL_FIELDS))
        if unknown:
            raise FixtureError(f"memory[{i}] unknown fields {unknown}")
        if not all(isinstance(v, str) for v in note.values()):
            raise FixtureError(f"memory[{i}] fields must be strings")


def _words(text: str) -> set[str]:
    return {w for w in _WORD_RE.findall(text.lower()) if len(w) > 2}


class MockMemory:
    """In-memory notes exposing search_memory and save_memory to a target."""

    def __init__(self, notes: list[dict[str, Any]], log: ToolCallLog) -> None:
        check_memory(notes)
        self._notes = copy.deepcopy(notes)
        self.log = log

    @property
    def notes(self) -> list[dict[str, Any]]:
        return copy.deepcopy(self._notes)

    def search_memory(self, query: str | None = None, limit: int | str | None = None
                      ) -> list[dict[str, Any]]:
        """Notes ranked by words shared with the query; all notes, in order,
        without one."""
        limit = DEFAULT_LIMIT if limit is None else as_int("limit", limit, minimum=1)
        if query is not None:
            query = as_text("query", query)
        wanted = _words(query or "")
        ranked = sorted(enumerate(self._notes),
                        key=lambda p: (-len(wanted & _words(p[1]["content"])), p[0]))
        result = copy.deepcopy([n for _, n in ranked[:limit]])
        self.log.record("search_memory", {"query": query, "limit": limit}, result)
        return result

    def save_memory(self, content: str) -> dict[str, Any]:
        """Keep a note for later sessions (this run only)."""
        content = as_text("content", content)
        if not content.strip():
            raise ToolArgumentError("content must be the note to save")
        note_id = f"mem-saved-{sum(n.get('saved') == 'this session' for n in self._notes) + 1}"
        self._notes.append({"id": note_id, "saved": "this session", "content": content})
        result = {"status": "saved", "id": note_id}
        self.log.record("save_memory", {"content": content}, result)
        return result
