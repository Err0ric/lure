"""Mock shell tool: run_command.

Safety: this module never runs anything. A command is text: it is logged
and matched against canned output from a JSON fixture. A command with no
canned output gets exit code 127 and a note that nothing ran. There is no
process, no shell and no network here. Every call is recorded in the shared
ToolCallLog, with its return value, for the Judge.
"""

from __future__ import annotations

import copy
import re
from typing import Any

from lure.tools.args import ToolArgumentError, as_text
from lure.tools.call_log import ToolCallLog
from lure.tools.mock_email import FixtureError

NOT_FOUND = {"exit_code": 127, "stdout": "",
             "stderr": "mock shell: no canned output for this command; nothing ran"}


def check_shell(entries: Any) -> None:
    """A shell fixture is a JSON list of {match, stdout} with an optional
    integer exit_code. match is part of a command, on word boundaries (agents
    often prefix one with cd or chain several)."""
    if not isinstance(entries, list):
        raise FixtureError("shell fixture must be a JSON list")
    for i, e in enumerate(entries):
        if not isinstance(e, dict) or not {"match", "stdout"} <= set(e) or not set(e) <= {
                "match", "stdout", "exit_code"}:
            raise FixtureError(f"shell[{i}] must have match and stdout, and optionally exit_code")
        if not isinstance(e["match"], str) or not e["match"].strip():
            raise FixtureError(f"shell[{i}] match must be a non-empty string")
        if not isinstance(e["stdout"], str):
            raise FixtureError(f"shell[{i}] stdout must be a string")
        if not isinstance(e.get("exit_code", 0), int) or isinstance(e.get("exit_code"), bool):
            raise FixtureError(f"shell[{i}] exit_code must be an integer")


def _key(command: str) -> str:
    return " ".join(command.split())


# Where one shell word ends and the next begins. A match may also follow a
# path ("./run_tests.sh" matches "run_tests.sh").
_EDGE = r"[\s;&|()]"
_START = r"[\s;&|()/]"


def _matches(match: str, command: str) -> bool:
    return re.search(rf"(?:^|{_START}){re.escape(_key(match))}(?:$|{_EDGE})", command) is not None


class MockShell:
    """Canned command output exposing run_command to a target."""

    def __init__(self, entries: list[dict[str, Any]], log: ToolCallLog) -> None:
        check_shell(entries)
        self._entries = copy.deepcopy(entries)
        self.log = log

    def run_command(self, command: str) -> dict[str, Any]:
        """Return the canned output of the first entry whose match is in the
        command as whole words (spacing does not matter): "ls" matches
        "cd x && ls", not "ledgerbox-tools". Nothing is executed."""
        command = as_text("command", command)
        if not command.strip():
            raise ToolArgumentError("command must be the shell command to run")
        key = _key(command)
        entry = next((e for e in self._entries if _matches(e["match"], key)), None)
        result = (dict(NOT_FOUND) if entry is None else
                  {"exit_code": entry.get("exit_code", 0), "stdout": entry["stdout"], "stderr": ""})
        self.log.record("run_command", {"command": command}, copy.deepcopy(result))
        return result
