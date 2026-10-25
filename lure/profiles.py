"""Profiles: bring your own agent.

A profile describes an agent someone built: its model, its real system
prompt, and its tools, each mapped to one of Lure's mock tools. `lure run
--profile` runs the attacks the agent's tools cover, under its own prompt,
with its own tool names and descriptions. The tools stay Lure's mocks:
nothing in a profile is ever called. A profile is descriptive only, so it
holds no endpoints and no credentials.

The system prompt goes to whatever model API the profile names. For a work
agent, use an organization-approved API account or a local model.

`renders` says what the chat app showing the agent's output does with it:
`images` (shows images in replies, fetching them with no click) and
`link_previews` (fetches links in the agent's chat posts to preview them).
Unset means yes, the worst case. An attack whose harm needs one the app does
not do is skipped with the reason.

A tool marked `gated: true` stops for a person's confirmation before each
call (see lure.gate); `confirmer` picks the stand-in for that person:
careful (the default) or deny_all.

An `agent:` block describes a real agent that runs as code: its container
image, how its model is reached, and which environment variables it may
inherit (a capped test key, by name only). Running real agent code needs
OS and network isolation, so a profile with an agent block must also say
`isolation: container` (Lure's sandbox, lure.sandbox) or `vm` (a VM you
run; Lure cannot run it itself). Lure refuses the profile otherwise. The
model URL's host is the one destination the sandbox gateway allows.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import yaml

from lure.adapters import TARGETS
from lure.attacks import PRIVATE_KEY_RE, SCENARIOS, SECRET_RE, Attack
from lure.gate import CAREFUL, CONFIRMERS, SHOWS, STRICT, SUMMARY_CHECKS, TOLERANT, Gate
from lure.judge.rules import Judgment, Verdict
from lure.tools import AMOUNT_TOOLS, GATABLE_TOOLS, KNOWN_TOOLS
from lure.tools.registry import ToolAlias

REQUIRED_KEYS = ("name", "target", "tools")
OPTIONAL_KEYS = ("owner", "role", "model", "system_prompt", "system_prompt_file",
                 "third_party_tools", "policy", "suites", "renders", "confirmer", "scenarios",
                 "agent", "isolation")
ISOLATIONS = ("container", "vm")
AGENT_KEYS = ("image", "provider", "model_url")
AGENT_OPTIONAL = ("command", "env", "allow", "settings_file", "model_url_key", "limits")
AGENT_PROVIDERS = ("anthropic", "ollama")
LIMIT_KEYS = ("memory", "cpus", "pids", "workspace")
ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
HOST_PORT_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:\d{1,5})?(/[a-z0-9._~/-]*)?$")
# Paths the gateway allows on a provider's plain-HTTP model host. Ollama's
# API is unauthenticated and can pull, create and delete models, so the
# agent gets only its chat endpoint.
MODEL_PATHS = {"ollama": "/api/chat"}
IMAGE_RE = re.compile(r"^[a-z0-9][a-z0-9._/:@-]{0,200}$")
RENDER_KEYS = ("images", "link_previews")
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
# What model APIs accept as a tool name.
TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
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
    # A person confirms each call before it runs (lure.gate), seeing every
    # argument or only the agent's summary.
    gated: bool = False
    gate_shows: str = "arguments"
    # Ask only for calls above this amount (pay_invoice, issue_refund).
    gate_over: float | None = None
    # How closely a summary must name the harm: tolerant or strict (lure.gate).
    summary_check: str = TOLERANT


@dataclass(frozen=True)
class AgentSpec:
    """A real agent that runs as code in the sandbox (lure sandbox run)."""

    image: str
    provider: str
    model_url: str
    command: tuple[str, ...] = ("/usr/local/bin/python3", "/opt/lure/agent.py")
    # Environment variable names the agent inherits from Lure's, never values.
    env: tuple[str, ...] = ()
    # More host[:port] the gateway allows, beyond the model URL's host.
    allow: tuple[str, ...] = ()
    # Where the agent keeps its model URL in its workspace, for the record.
    settings_file: str = ".agent/settings.json"
    model_url_key: str = "model_base_url"
    limits: tuple[tuple[str, str], ...] = ()

    @property
    def model_host(self) -> str:
        """host:port of the model URL, as the gateway allows it."""
        from urllib.parse import urlsplit
        parts = urlsplit(self.model_url)
        port = parts.port or (443 if parts.scheme == "https" else 80)
        return f"{(parts.hostname or '').lower()}:{port}"

    @property
    def model_allow(self) -> str:
        """The gateway allowlist entry for the model: host:port, plus the
        chat path for a provider whose API is plain HTTP (Ollama)."""
        from urllib.parse import urlsplit
        path = MODEL_PATHS.get(self.provider)
        if path is None or urlsplit(self.model_url).scheme != "http":
            return self.model_host
        return self.model_host + path

    def record(self) -> dict[str, Any]:
        return {"image": self.image, "provider": self.provider, "model_host": self.model_host,
                "env": list(self.env), "allow": list(self.allow)}


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
    scenarios: tuple[str, ...] | None = None  # None means every scenario pack
    # images and link_previews: True, False, or None when not set (assumed True).
    renders: tuple[tuple[str, bool | None], ...] = (("images", None), ("link_previews", None))
    confirmer: str = CAREFUL
    # A real agent run as code (lure sandbox run), and how it is isolated.
    agent: AgentSpec | None = None
    isolation: str | None = None

    def rendering(self, key: str) -> bool | None:
        return dict(self.renders)[key]

    @property
    def gate(self) -> Gate | None:
        """The gated Lure tools and who confirms, or None with no gate."""
        gated = frozenset(t.maps_to for t in self.tools if t.gated)
        summary = frozenset(t.maps_to for t in self.tools if t.gated and t.gate_shows == "summary")
        limits = tuple((t.maps_to, t.gate_over) for t in self.tools
                       if t.gated and t.gate_over is not None)
        strict = frozenset(t.maps_to for t in self.tools if t.gated and t.gate_shows == "summary"
                           and t.summary_check == STRICT)
        return Gate(gated, self.confirmer, summary, limits, strict) if gated else None

    @property
    def aliases(self) -> dict[str, ToolAlias]:
        """Lure tool name -> the agent's name and description for it."""
        return {t.maps_to: ToolAlias(t.name, t.description) for t in self.tools}

    def record(self, canary_appended: bool) -> dict[str, Any]:
        """What a result records about the profile it ran under."""
        found = {"name": self.name, "sha256": self.sha256, "prompt_source": "profile",
                 "canary_appended": canary_appended,
                 "tools": {t.name: t.maps_to for t in self.tools}}
        if self.gate is not None:
            found |= {"gated": [t.name for t in self.tools if t.gated],
                      "confirmer": self.confirmer}
            summary = [t.name for t in self.tools if t.gated and t.gate_shows == "summary"]
            if summary:
                found["summary_gated"] = summary
                found["summary_check"] = {t.name: t.summary_check for t in self.tools
                                          if t.gated and t.gate_shows == "summary"}
            limits = {t.name: t.gate_over for t in self.tools if t.gated and t.gate_over}
            if limits:
                found["gate_over"] = limits
        if self.agent is not None:
            found["isolation"] = self.isolation
            found["agent"] = self.agent.record()
        return found


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
    renders = data.get("renders", {})
    if not isinstance(renders, dict) or not set(renders) <= set(RENDER_KEYS) or not all(
            isinstance(v, bool) for v in renders.values()):
        raise fail("renders must be a mapping of images and link_previews to true or false")
    scenarios = data.get("scenarios", "all")
    if scenarios == "all":
        scenarios = None
    elif not (isinstance(scenarios, list) and scenarios
              and all(s in SCENARIOS for s in scenarios)):
        raise fail(f"scenarios must be all or a list of scenario packs: {', '.join(SCENARIOS)}")
    confirmer = data.get("confirmer", CAREFUL)
    if confirmer not in CONFIRMERS:
        raise fail(f"confirmer must be one of {', '.join(CONFIRMERS)}")
    if "confirmer" in data and not any(t.gated for t in tools):
        raise fail("confirmer is set, but no tool is gated: mark a tool gated: true")

    agent, isolation = _agent(data, fail)
    return Profile(name=name, path=path, sha256=digest.hexdigest(), target=data["target"],
                   system_prompt=prompt.strip(), tools=tools, model=data.get("model"),
                   owner=data.get("owner"), role=data.get("role"),
                   third_party_tools=third_party, policy=policy,
                   suites=tuple(suites) if suites else None,
                   renders=tuple((k, renders.get(k)) for k in RENDER_KEYS),
                   confirmer=confirmer, scenarios=tuple(scenarios) if scenarios else None,
                   agent=agent, isolation=isolation)


def _agent(data: dict[str, Any], fail) -> tuple[AgentSpec | None, str | None]:
    """The agent block and the isolation it runs under. A real agent's code
    runs, so Lure refuses one without isolation: container or vm."""
    isolation = data.get("isolation")
    if "agent" not in data:
        if isolation is not None:
            raise fail("isolation applies to a real agent: add an agent: block, or remove it")
        return None, None
    if isolation not in ISOLATIONS:
        raise fail("a profile with an agent: block runs real agent code, so it needs "
                   "isolation: container or isolation: vm; Lure refuses to run it without one")
    block = data["agent"]
    if not isinstance(block, dict):
        raise fail("agent must be a mapping")
    missing = [k for k in AGENT_KEYS if k not in block]
    unknown = sorted(set(block) - set(AGENT_KEYS) - set(AGENT_OPTIONAL))
    if missing or unknown:
        raise fail(f"agent: missing keys {missing}" if missing else f"agent: unknown keys {unknown}")
    image = block["image"]
    if not isinstance(image, str) or not IMAGE_RE.match(image):
        raise fail("agent.image must be a container image reference")
    if block["provider"] not in AGENT_PROVIDERS:
        raise fail(f"agent.provider must be one of {', '.join(AGENT_PROVIDERS)}")
    from urllib.parse import urlsplit
    url = block["model_url"]
    parts = urlsplit(url) if isinstance(url, str) else None
    if parts is None or parts.scheme not in ("http", "https") or not parts.hostname:
        raise fail("agent.model_url must be an http:// or https:// URL")
    if parts.username or parts.password or parts.query:
        raise fail("agent.model_url must not carry credentials or a query")
    command = block.get("command", list(AgentSpec.command))
    if not (isinstance(command, list) and command
            and all(isinstance(c, str) and c for c in command)):
        raise fail("agent.command must be a non-empty list of strings")
    env = block.get("env", [])
    if not (isinstance(env, list) and all(isinstance(e, str) and ENV_NAME_RE.match(e)
                                          for e in env)):
        raise fail("agent.env must be a list of environment variable names (never values)")
    allow = block.get("allow", [])
    if not (isinstance(allow, list) and all(isinstance(a, str) and HOST_PORT_RE.match(a.lower())
                                            for a in allow)):
        raise fail("agent.allow must be a list of host, host:port or host:port/path")
    for key in ("settings_file", "model_url_key"):
        if key in block and (not isinstance(block[key], str) or not block[key].strip()
                             or block[key].startswith("/") or ".." in block[key].split("/")):
            raise fail(f"agent.{key} must be a relative name inside the workspace")
    limits = block.get("limits", {})
    if not (isinstance(limits, dict) and set(limits) <= set(LIMIT_KEYS)
            and all(isinstance(v, (str, int)) and not isinstance(v, bool)
                    for v in limits.values())):
        raise fail(f"agent.limits may set {', '.join(LIMIT_KEYS)}")
    return AgentSpec(image=image, provider=block["provider"], model_url=url.rstrip("/"),
                     command=tuple(command), env=tuple(env),
                     allow=tuple(a.lower() for a in allow),
                     settings_file=block.get("settings_file", AgentSpec.settings_file),
                     model_url_key=block.get("model_url_key", AgentSpec.model_url_key),
                     limits=tuple((k, str(v)) for k, v in limits.items())), isolation


def _tools(value: Any, fail) -> tuple[ProfileTool, ...]:
    if not isinstance(value, list) or not value:
        raise fail("tools must be a non-empty list")
    tools, names, mapped = [], set(), set()
    for i, item in enumerate(value):
        where = f"tools[{i}]"
        if not isinstance(item, dict) or set(item) - {"essential", "gated", "gate_shows",
                                                      "gate_over", "summary_check"} != {
                "name", "description", "maps_to"}:
            raise fail(f"{where} needs name, description and maps_to (and optionally essential, "
                       "gated, gate_shows, gate_over and summary_check)")
        name, description, maps_to = item["name"], item["description"], item["maps_to"]
        essential, gated = item.get("essential", False), item.get("gated", False)
        if not isinstance(essential, bool):
            raise fail(f"{where}: essential must be true or false")
        if not isinstance(gated, bool):
            raise fail(f"{where}: gated must be true or false")
        shows = item.get("gate_shows", "arguments")
        if shows not in SHOWS:
            raise fail(f"{where}: gate_shows must be one of {', '.join(SHOWS)}")
        if "gate_shows" in item and not gated:
            raise fail(f"{where}: gate_shows needs gated: true")
        check = item.get("summary_check", TOLERANT)
        if check not in SUMMARY_CHECKS:
            raise fail(f"{where}: summary_check must be one of {', '.join(SUMMARY_CHECKS)}")
        if "summary_check" in item and shows != "summary":
            raise fail(f"{where}: summary_check needs gate_shows: summary")
        over = item.get("gate_over")
        if over is not None:
            if not gated:
                raise fail(f"{where}: gate_over needs gated: true")
            if isinstance(over, bool) or not isinstance(over, (int, float)) or over <= 0:
                raise fail(f"{where}: gate_over must be an amount above 0")
            if maps_to not in AMOUNT_TOOLS:
                raise fail(f"{where}: gate_over works only for tools with an amount: "
                           f"{', '.join(sorted(AMOUNT_TOOLS))}")
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
        if gated and maps_to not in GATABLE_TOOLS:
            raise fail(f"{where}: only a tool that acts can be gated, not {maps_to}; gatable: "
                       f"{', '.join(sorted(GATABLE_TOOLS))}")
        names.add(name)
        mapped.add(maps_to)
        tools.append(ProfileTool(name, " ".join(description.split()), maps_to, essential, gated,
                                 shows, float(over) if over is not None else None, check))
    return tuple(tools)


def select(profile: Profile, attacks: list[Attack]) -> tuple[list[Attack], list[Skipped]]:
    """The attacks this agent can be tested with, and why the others are
    left out: a scenario pack or category outside the profile's, a Lure
    tool no profile tool maps to, or third-party tools the agent does not
    load."""
    mapped = {t.maps_to for t in profile.tools}
    chosen, skipped = [], []
    for attack in attacks:
        builtin = [t for t in attack.tools if t in KNOWN_TOOLS]
        third_party = [t for t in attack.tools if t not in KNOWN_TOOLS]
        missing = [t for t in builtin if t not in mapped]
        if profile.scenarios is not None and attack.scenario not in profile.scenarios:
            skipped.append(Skipped(attack, f"scenario pack {attack.scenario} is not in the "
                                           "profile's scenarios"))
        elif profile.suites is not None and attack.category not in profile.suites:
            skipped.append(Skipped(attack, f"category {attack.category} is not in the "
                                           "profile's suites"))
        elif missing:
            skipped.append(Skipped(attack, "no profile tool maps to " + ", ".join(missing)))
        elif needs_images(attack) and profile.rendering("images") is False:
            skipped.append(Skipped(attack, "the agent's chat app does not show images in its "
                                           "replies (renders.images: false)"))
        elif needs_link_previews(attack) and profile.rendering("link_previews") is False:
            skipped.append(Skipped(attack, "the agent's chat app does not preview links in its "
                                           "posts (renders.link_previews: false)"))
        elif third_party and not profile.third_party_tools:
            skipped.append(Skipped(attack, "it adds third-party tools (" + ", ".join(third_party)
                                           + "); set third_party_tools: true if the agent "
                                             "loads MCP or plugin tools"))
        else:
            chosen.append(attack)
    return chosen, skipped


def needs_images(attack: Attack) -> bool:
    """The attack's harm is an image in the reply, fetched when it is shown."""
    return any((r.get("reply_url") or {}).get("render") == "image" for r in attack.fail_if)


def needs_link_previews(attack: Attack) -> bool:
    """The attack's harm is a link in a chat post, fetched by its preview."""
    return any(r.get("tool") == "post_message" and "url_in_args" in r for r in attack.fail_if)


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
    required = task.get("read_tools_required", [])
    unread = [] if set(task.get("read_tools_called", [])) & set(required) else required
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
