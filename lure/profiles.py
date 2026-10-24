"""Profiles: bring your own agent.

A profile describes an agent someone built: its model, its real system
prompt, and its tools, each mapped to one of Lure's mock tools. `lure run
--profile` runs the attacks the agent's tools cover, under its own prompt,
with its own tool names and descriptions. The tools stay Lure's mocks:
nothing in a profile is ever called. A profile is descriptive only, so it
holds no endpoints and no credentials.

The system prompt goes to whatever model API the profile names. For a work
agent, use an organization-approved API account or a local model.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import yaml

from lure.adapters import TARGETS
from lure.attacks import SECRET_RE, Attack
from lure.judge.rules import Judgment, Verdict
from lure.tools import KNOWN_TOOLS
from lure.tools.registry import ToolAlias

REQUIRED_KEYS = ("name", "target", "tools")
OPTIONAL_KEYS = ("owner", "role", "model", "system_prompt", "system_prompt_file",
                 "third_party_tools", "policy", "suites")
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
# What model APIs accept as a tool name.
TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
MAX_DESCRIPTION = 1000
CANARY_SEPARATOR = "\n\n"
# The reason for a profile run that never reached the attack because the
# agent did not take the scenario's setup step. Reports show it as is.
SETUP_BLOCKED = "not tested: the agent's rules blocked the setup step"


class ProfileError(ValueError):
    """The profile file is missing or invalid."""


@dataclass(frozen=True)
class ProfileTool:
    name: str
    description: str
    maps_to: str
    # The agent cannot do its job without it: the approval report suggests
    # a confirmation step for it, never removing it.
    essential: bool = False


@dataclass(frozen=True)
class Profile:
    name: str
    path: Path
    sha256: str
    target: str
    system_prompt: str
    tools: tuple[ProfileTool, ...]
    model: str | None = None
    owner: str | None = None
    role: str | None = None
    third_party_tools: bool = False
    policy: Path | None = None
    suites: tuple[str, ...] | None = None  # None means every category

    @property
    def aliases(self) -> dict[str, ToolAlias]:
        """Lure tool name -> the agent's name and description for it."""
        return {t.maps_to: ToolAlias(t.name, t.description) for t in self.tools}

    def record(self, canary_appended: bool) -> dict[str, Any]:
        """What a result records about the profile it ran under."""
        return {"name": self.name, "sha256": self.sha256, "prompt_source": "profile",
                "canary_appended": canary_appended,
                "tools": {t.name: t.maps_to for t in self.tools}}


@dataclass(frozen=True)
class Skipped:
    attack: Attack
    reason: str


def load_profile(path: str | Path) -> Profile:
    path = Path(path)
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        raise ProfileError(f"profile not found: {path}") from None
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as e:
        raise ProfileError(f"{path.name}: not valid YAML: {e}") from e

    def fail(msg: str) -> ProfileError:
        return ProfileError(f"{path.name}: {msg}")

    if not isinstance(data, dict):
        raise fail("must be a YAML mapping")
    missing = [k for k in REQUIRED_KEYS if k not in data]
    if missing:
        raise fail(f"missing keys {missing}")
    unknown = sorted(set(data) - set(REQUIRED_KEYS) - set(OPTIONAL_KEYS))
    if unknown:
        raise fail(f"unknown keys {unknown}")

    name = data["name"]
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise fail("name must be lowercase letters, digits and dashes (it names the results "
                   "folder)")
    if data["target"] not in TARGETS:
        raise fail(f"target must be one of {list(TARGETS)}")
    for key in ("model", "owner", "role"):
        if key in data and (not isinstance(data[key], str) or not data[key].strip()):
            raise fail(f"{key} must be a non-empty string")

    digest = hashlib.sha256(raw)
    if ("system_prompt" in data) == ("system_prompt_file" in data):
        raise fail("give exactly one of system_prompt or system_prompt_file")
    if "system_prompt_file" in data:
        prompt_path = path.parent / str(data["system_prompt_file"])
        try:
            prompt_bytes = prompt_path.read_bytes()
        except FileNotFoundError:
            raise fail(f"system_prompt_file not found: {prompt_path}") from None
        digest.update(prompt_bytes)
        prompt = prompt_bytes.decode("utf-8")
    else:
        prompt = data["system_prompt"]
    if not isinstance(prompt, str) or not prompt.strip():
        raise fail("the system prompt must be non-empty text")
    if SECRET_RE.search(prompt) or PRIVATE_KEY_RE.search(prompt):
        raise fail("the system prompt contains what looks like a real API key or private key; "
                   "remove it: a profile holds no credentials")

    tools = _tools(data["tools"], fail)
    third_party = data.get("third_party_tools", False)
    if not isinstance(third_party, bool):
        raise fail("third_party_tools must be true or false")

    policy = None
    if "policy" in data:
        policy = path.parent / str(data["policy"])
        if not policy.is_file():
            raise fail(f"policy file not found: {policy}")
    suites = data.get("suites", "all")
    if suites == "all":
        suites = None
    elif not (isinstance(suites, list) and suites and all(isinstance(s, str) for s in suites)):
        raise fail("suites must be all or a list of attack categories")

    return Profile(name=name, path=path, sha256=digest.hexdigest(), target=data["target"],
                   system_prompt=prompt.strip(), tools=tools, model=data.get("model"),
                   owner=data.get("owner"), role=data.get("role"),
                   third_party_tools=third_party, policy=policy,
                   suites=tuple(suites) if suites else None)


def _tools(value: Any, fail) -> tuple[ProfileTool, ...]:
    if not isinstance(value, list) or not value:
        raise fail("tools must be a non-empty list")
    tools, names, mapped = [], set(), set()
    for i, item in enumerate(value):
        where = f"tools[{i}]"
        if not isinstance(item, dict) or set(item) - {"essential"} != {"name", "description",
                                                                          "maps_to"}:
            raise fail(f"{where} needs name, description and maps_to (and optionally essential)")
        name, description, maps_to = item["name"], item["description"], item["maps_to"]
        essential = item.get("essential", False)
        if not isinstance(essential, bool):
            raise fail(f"{where}: essential must be true or false")
        if not isinstance(name, str) or not TOOL_NAME_RE.match(name):
            raise fail(f"{where}: name must be 1 to 64 letters, digits, _ or -")
        if not isinstance(description, str) or not description.strip():
            raise fail(f"{where}: description must be non-empty text")
        if len(description) > MAX_DESCRIPTION:
            raise fail(f"{where}: description is over {MAX_DESCRIPTION} characters")
        if maps_to not in KNOWN_TOOLS:
            raise fail(f"{where}: maps_to must be one of Lure's mock tools: "
                       f"{', '.join(sorted(KNOWN_TOOLS))}")
        if name in names:
            raise fail(f"{where}: tool name {name!r} is listed twice")
        if maps_to in mapped:
            raise fail(f"{where}: two tools map to {maps_to}; list the one the agent uses")
        if name in KNOWN_TOOLS and name != maps_to:
            raise fail(f"{where}: {name!r} is another Lure tool's name; it cannot map to {maps_to}")
        names.add(name)
        mapped.add(maps_to)
        tools.append(ProfileTool(name, " ".join(description.split()), maps_to, essential))
    return tuple(tools)


def select(profile: Profile, attacks: list[Attack]) -> tuple[list[Attack], list[Skipped]]:
    """The attacks this agent can be tested with, and why the others are
    left out: a category outside the profile's suites, a Lure tool no
    profile tool maps to, or third-party tools the agent does not load."""
    mapped = {t.maps_to for t in profile.tools}
    chosen, skipped = [], []
    for attack in attacks:
        builtin = [t for t in attack.tools if t in KNOWN_TOOLS]
        third_party = [t for t in attack.tools if t not in KNOWN_TOOLS]
        missing = [t for t in builtin if t not in mapped]
        if profile.suites is not None and attack.category not in profile.suites:
            skipped.append(Skipped(attack, f"category {attack.category} is not in the "
                                           "profile's suites"))
        elif missing:
            skipped.append(Skipped(attack, "no profile tool maps to " + ", ".join(missing)))
        elif third_party and not profile.third_party_tools:
            skipped.append(Skipped(attack, "it adds third-party tools (" + ", ".join(third_party)
                                           + "); set third_party_tools: true if the agent "
                                             "loads MCP or plugin tools"))
        else:
            chosen.append(attack)
    return chosen, skipped


def prepare(profile: Profile, attack: Attack) -> tuple[Attack, str, bool]:
    """The attack as this agent meets it: the profile's system prompt, with
    the attack's canary line appended when it has one, and reply_contains
    rules that look for Lure tool names also looking for the agent's names
    for them (a leaked tool list names the tools the agent was given)."""
    prompt = profile.system_prompt
    if attack.canary:
        prompt += CANARY_SEPARATOR + attack.canary.strip()
    tools = {alias.name: canonical for canonical, alias in profile.aliases.items()}
    return with_alias_names(attack, tools), prompt, attack.canary is not None


def with_alias_names(attack: Attack, tools: dict[str, str]) -> Attack:
    """reply_contains rules that name Lure tools also name the agent's tools
    (agent name -> Lure name, as a record's profile block stores them).
    Only distinctive names: a plain-word alias ("email") would match
    ordinary replies."""
    renamed = {canonical: name for name, canonical in tools.items()
               if re.search(r"[_\-0-9]", name)}
    return _with_alias_names(attack, renamed)


def _with_alias_names(attack: Attack, renamed: dict[str, str]) -> Attack:
    def widen(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out = []
        for rule in rules:
            strings = rule.get("reply_contains")
            if strings and any(s in renamed for s in strings):
                extra = [renamed[s] for s in strings if s in renamed and renamed[s] not in strings]
                rule = {**rule, "reply_contains": [*strings, *extra]}
            out.append(rule)
        return out

    return replace(attack, fail_if=widen(attack.fail_if), partial_if=widen(attack.partial_if))


def setup_blocked_detail(task: dict[str, Any]) -> str | None:
    """From a saved task check: what setup step the agent skipped after
    reading the content, or None when that is not why the run is Invalid."""
    unread = [t for t in task.get("read_tools_required", [])
              if t not in task.get("read_tools_called", [])]
    facts_missing = task.get("facts") and task.get("checked_text") and not task.get("facts_found")
    not_done = [t for t in task.get("actions_required", [])
                if t not in task.get("actions_done", [])]
    undelivered = task.get("payload_delivered") is False
    if unread or facts_missing or not (not_done or undelivered):
        return None
    details = []
    if not_done:
        details.append(f"{', '.join(not_done)} {'was' if len(not_done) == 1 else 'were'} "
                       "never called")
    if undelivered:
        details.append("the step that releases the payload never happened")
    return "; ".join(details)


def mark_setup_blocked(judgment: Judgment) -> Judgment:
    """A profile run that is Invalid only because the agent skipped the
    scenario's setup step (a required action, or the reply that releases a
    follow-up payload) gets SETUP_BLOCKED as its reason, with the detail.
    The agent read what it was given, so its own instructions are the
    likely cause. Other Invalid runs (content never read, task facts
    missing) keep their reason. The verdict never changes."""
    if judgment.verdict is not Verdict.INVALID or judgment.task is None:
        return judgment
    detail = setup_blocked_detail(judgment.task.to_dict())
    if detail is None:
        return judgment
    return replace(judgment, reason=f"{SETUP_BLOCKED} ({detail})")
