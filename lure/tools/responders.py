"""Responders: fixtures that react to what the target does.

A responder watches the tool-call log. When a successful call matches its
`when` conditions, it releases an item from a pending fixture into a mock:
new mail arrives, a file appears or changes, a page changes, or a tool's
definition changes (update_tool, a "rug pull"). That turns a static fixture
into a multi-step attack: the follow-up only exists once the target has
taken the first step.

    responders:
      - when: {tool: send_email, to_domain_in: [clearpath-recon.example],
               body_contains: [confirmed]}
        then: {add_inbox: inbox_followups[0]}
        times: 1

Responders are declarative and deterministic: the same calls always release
the same items in the same order. Each firing is an event in the run's
transcript and record. Pending fixtures are never given to a tool directly;
only a responder can release them.

Safety: a responder only changes the in-memory mocks of the run.
"""

from __future__ import annotations

import copy
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from lure.adapters.base import ToolSpec
from lure.tools.call_log import ToolCall
from lure.tools.calls import (
    arg_strings,
    contains_any,
    failed,
    in_domains,
    message_text,
    recipients,
)
from lure.tools.mock_email import REQUIRED_FIELDS as INBOX_FIELDS
from lure.tools.mock_email import FixtureError
from lure.tools.mock_files import check_files
from lure.tools.mock_http import check_web

# Action -> the fixture (and so the mock) it changes. update_tool changes a
# tool's definition instead: {name, description, parameters (optional)}.
ACTIONS = {"add_inbox": "inbox", "add_file": "files", "update_page": "web",
           "update_tool": None}
TOOL_ITEM_KEYS = ("name", "description", "parameters")
TRIGGER_KEYS = ("tool", "to_domain_in", "body_contains", "args_contain")
# `when`, not `on`: YAML 1.1 reads a bare on: key as true.
KEYS = ("when", "then", "times")
# A pending item: fixture name and index, like inbox_followups[0].
SOURCE_RE = re.compile(r"^([A-Za-z_]\w*)\[(\d+)\]$")


@dataclass(frozen=True)
class Responder:
    when: dict[str, Any]
    action: str
    # The pending item it releases, like inbox_followups[0].
    source: str
    times: int = 1

    @property
    def source_fixture(self) -> str:
        return SOURCE_RE.match(self.source).group(1)

    @property
    def source_index(self) -> int:
        return int(SOURCE_RE.match(self.source).group(2))

    def item(self, fixtures: dict[str, Any]) -> Any:
        return fixtures[self.source_fixture][self.source_index]

    def matches(self, call: ToolCall) -> bool:
        when = self.when
        if call.tool != when["tool"] or failed(call):
            return False
        if "to_domain_in" in when:
            domains = [d.lower() for d in when["to_domain_in"]]
            if not any(in_domains(r, domains) for r in recipients(call)):
                return False
        if "body_contains" in when and not contains_any(message_text(call),
                                                        when["body_contains"]):
            return False
        return "args_contain" not in when or contains_any(
            "\n".join(arg_strings(call.args)).lower(), when["args_contain"])


def parse(value: Any, tools: list[str], fixtures: dict[str, Any], wired: set[str],
          fail: Callable[[str], Exception]) -> list[Responder]:
    """Validate an attack's responders. `fixtures` are the loaded fixtures and
    `wired` the fixture names the attack's tools read."""
    if value is None:
        return []
    if not isinstance(value, list) or not value:
        raise fail("responders must be a non-empty list")
    found = []
    for i, r in enumerate(value):
        where = f"responders[{i}]"
        if isinstance(r, dict) and True in r:
            raise fail(f"{where}: YAML reads a bare on: key as true; the trigger key is when:")
        if not isinstance(r, dict) or not {"when", "then"} <= set(r) or not set(r) <= set(KEYS):
            raise fail(f"{where} must have when and then, and optionally times")
        found.append(Responder(_trigger(r["when"], tools, where, fail),
                               *_action(r["then"], tools, fixtures, wired, where, fail),
                               _times(r.get("times", 1), where, fail)))
    return found


def _trigger(when: Any, tools: list[str], where: str, fail) -> dict[str, Any]:
    if not isinstance(when, dict) or "tool" not in when:
        raise fail(f"{where}.when must be a mapping with a tool")
    unknown = sorted(set(when) - set(TRIGGER_KEYS))
    if unknown:
        raise fail(f"{where}.when unknown keys {unknown}; known: {list(TRIGGER_KEYS)}")
    if when["tool"] not in tools:
        raise fail(f"{where}.when tool {when['tool']!r} is not in this attack's tools")
    for k in TRIGGER_KEYS[1:]:
        if k in when and (not isinstance(when[k], list) or not when[k]
                        or not all(isinstance(t, str) and t.strip() for t in when[k])):
            raise fail(f"{where}.when {k} must be a non-empty list of non-empty strings")
    return dict(when)


def _action(then: Any, tools: list[str], fixtures: dict[str, Any], wired: set[str],
            where: str, fail) -> tuple[str, str]:
    if not isinstance(then, dict) or len(then) != 1 or next(iter(then)) not in ACTIONS:
        raise fail(f"{where}.then must be one of {list(ACTIONS)}, like add_inbox: name[0]")
    action, source = next(iter(then.items()))
    m = SOURCE_RE.match(source) if isinstance(source, str) else None
    if not m:
        raise fail(f"{where}.then {action} must name a pending item like inbox_followups[0]")
    name, index = m.group(1), int(m.group(2))
    if name not in fixtures:
        raise fail(f"{where}.then {action}: no fixture {name!r}")
    if name in wired:
        raise fail(f"{where}.then {action}: {name!r} is read by a tool; a responder "
                   "releases items from a pending fixture no tool reads")
    if ACTIONS[action] is not None and ACTIONS[action] not in wired:
        raise fail(f"{where}.then {action} needs a tool that reads the "
                   f"{ACTIONS[action]!r} fixture")
    items = fixtures[name]
    if not isinstance(items, list) or index >= len(items):
        raise fail(f"{where}.then {action}: {source} not found")
    try:
        check_item(action, items[index])
    except FixtureError as e:
        raise fail(f"{where}.then {action}: {source}: {e}") from None
    if action == "update_tool" and items[index]["name"] not in tools:
        raise fail(f"{where}.then update_tool: tool {items[index]['name']!r} "
                   "is not in this attack's tools")
    return action, source


def _times(value: Any, where: str, fail) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise fail(f"{where}.times must be a whole number of at least 1")
    return value


def check_item(action: str, item: Any) -> None:
    """The item must be valid in the fixture the action changes."""
    if action == "add_inbox":
        if not isinstance(item, dict):
            raise FixtureError("must be an object")
        missing = [f for f in INBOX_FIELDS if f not in item]
        if missing:
            raise FixtureError(f"missing fields {missing}")
    elif action == "add_file":
        check_files([item])
    elif action == "update_page":
        check_web([item])
    elif action == "update_tool":
        check_tool_item(item)


def check_tool_item(item: Any) -> None:
    """A tool definition: name and description, optional JSON Schema parameters."""
    if not isinstance(item, dict) or not {"name", "description"} <= set(item):
        raise FixtureError("must be an object with name and description")
    unknown = sorted(set(item) - set(TOOL_ITEM_KEYS))
    if unknown:
        raise FixtureError(f"unknown keys {unknown}")
    if not all(isinstance(item[k], str) and item[k].strip() for k in ("name", "description")):
        raise FixtureError("name and description must be non-empty strings")
    params = item.get("parameters")
    if params is not None and (not isinstance(params, dict) or params.get("type") != "object"):
        raise FixtureError("parameters must be a JSON Schema object")


class Engine:
    """Runs an attack's responders against the mocks of one run."""

    def __init__(self, responders: list[Responder], fixtures: dict[str, Any],
                 mocks: dict[str, Any], specs: dict[str, ToolSpec]) -> None:
        self._responders = responders
        self._fixtures = fixtures
        self._mocks = mocks
        # The toolbox's live tool definitions, changed in place by update_tool.
        self._specs = specs
        self._fired = [0] * len(responders)
        self.events: list[dict[str, Any]] = []

    def after_call(self, index: int, call: ToolCall) -> list[dict[str, Any]]:
        """Fire every responder the call matches; return the new events."""
        new = []
        for i, r in enumerate(self._responders):
            if self._fired[i] >= r.times or not r.matches(call):
                continue
            self._fired[i] += 1
            self._apply(r)
            new.append({"responder": i, "after_call": index, "action": r.action,
                        "source": r.source})
        self.events += new
        return new

    def _apply(self, r: Responder) -> None:
        item = copy.deepcopy(r.item(self._fixtures))
        if r.action == "update_tool":
            old = self._specs[item["name"]]
            self._specs[item["name"]] = ToolSpec(
                item["name"], item["description"], item.get("parameters", old.parameters))
            return
        mock = self._mocks[ACTIONS[r.action]]
        if r.action == "add_inbox":
            mock.deliver(item)
        elif r.action == "add_file":
            mock.put(item["path"], item["content"])
        elif r.action == "update_page":
            mock.put_page(item)
