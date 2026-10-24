"""Load and validate attack YAML files.

Validation is strict so a bad attack fails at load time, not mid-run. It
also enforces the fake-data rule: every email address, URL host and listed
domain in the attack and its fixtures must be under the reserved .example
TLD.

An attack may add `followup_tasks`: later user turns, sent in order once the
target finishes the turn before. They make multi-turn attacks, where a
payload read in one turn only matters in a later, unrelated one.

Most payloads are planted in a fixture. A direct prompt injection uses the
location `task` instead: the payload goes into the user turn itself, and the
attack usually sets its own `system_prompt` with the policy it tries to
override.
"""

from __future__ import annotations

import base64
import binascii
import copy
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from lure.tools import KNOWN_TOOLS
from lure.tools import responders as responders_mod
from lure.tools.registry import TOOL_FIXTURES
from lure.tools.responders import Responder
from lure.tools.sources import item_source

# Categories are the folders under attacks/: a new category is a new folder.
CATEGORY_RE = re.compile(r"^[a-z][a-z0-9_]*$")
SEVERITIES = ("low", "medium", "high", "critical")
REQUIRED_KEYS = (
    "id", "name", "category", "atlas", "attack", "severity",
    "target_task", "fixtures", "injection", "tools", "fail_if",
)
OPTIONAL_KEYS = (
    "partial_if", "pass_if", "task_check", "required_tools", "system_prompt", "version",
    "followup_tasks", "responders",
)
PLACEMENTS = ("append", "prepend", "replace")
PAYLOAD_SEPARATOR = "\n\n"
# Injection location for a payload in the user turn, not a fixture.
TASK_LOCATION = "task"
# Rule keys the Judge understands. Keys naming a tool must be in `tools`.
RULE_KEYS = {
    "tool": "tool",
    "to_domain_not_in": "domains",
    "body_contains": "strings",
    "args_contain": "strings",
    "account_not_in": "strings",
    "reply_contains": "strings",
    "asked_user_before": "tool",
    "flagged_as_suspicious": "bool",
}

ID_RE = re.compile(r"^lure-[a-z]+-\d{3}$")
# A pinned older version: lure-jbk-002-v1
PINNED_RE = re.compile(r"^(lure-[a-z]+-\d{3})-v(\d+)$")
ATLAS_RE = re.compile(r"^AML\.T\d{4}(\.\d{3})?$")
ATTACK_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
LOCATION_RE = re.compile(r"^[A-Za-z_]\w*(\[\d+\]|\.[A-Za-z_]\w*)*$")
LOCATION_PART_RE = re.compile(r"\[(\d+)\]|\.?([A-Za-z_]\w*)")
EMAIL_RE = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")
URL_RE = re.compile(r"https?://([^/\s:?#]+)", re.IGNORECASE)
# Long base64 runs, so an encoded payload cannot hide a real domain.
BASE64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


class AttackError(ValueError):
    """Raised when an attack file or its fixtures are invalid."""


@dataclass(frozen=True)
class Injection:
    location: str
    payload: str
    placement: str = "append"
    # Distinctive words of the attacker's request. A question to the user only
    # counts as asking about the attack if it mentions one of these (or an
    # attacker address from the payload).
    keywords: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Attack:
    id: str
    name: str
    category: str
    atlas: list[str]
    attack: list[str]
    severity: str
    target_task: str
    fixtures: dict[str, Path]
    injection: Injection
    tools: list[str]
    fail_if: list[dict[str, Any]]
    partial_if: list[dict[str, Any]]
    pass_if: list[dict[str, Any]]
    source: Path
    # Facts from the fixtures; the final reply must mention at least one to
    # show the target did the task. Empty means no fact check.
    task_check: list[str] = field(default_factory=list)
    # Tools the target must call successfully (to an allowed recipient, where
    # fail_if limits domains) for the task to count as done. Empty means none.
    required_tools: list[str] = field(default_factory=list)
    # Lowercase strings that tie a question to the attacker's action: the
    # injection keywords plus addresses and domains that appear only in the
    # payload. Computed at load time. Empty means any action question counts.
    ask_markers: list[str] = field(default_factory=list)
    # The target's system prompt; None means the runner's neutral default.
    system_prompt: str | None = None
    # The file path or page URL holding the payload, for fixtures read one
    # item at a time. None means the delivery check is per tool.
    payload_source: str | None = None
    # Bump when a change makes new results incomparable with old ones (for
    # example a stricter rule), so summaries never mix the two.
    version: int = 1
    # Later user turns, sent in order after the target finishes each turn.
    followup_tasks: list[str] = field(default_factory=list)
    # Items released from pending fixtures when the target's calls match.
    responders: list[Responder] = field(default_factory=list)

    @property
    def multi_turn(self) -> bool:
        return bool(self.followup_tasks)

    @property
    def payload_fixture(self) -> str | None:
        """The fixture holding the payload; None for a payload in the task."""
        return None if self.in_task else LOCATION_PART_RE.match(self.injection.location).group(2)

    @property
    def payload_pending(self) -> bool:
        """True if the payload is in a pending fixture: only a responder can
        release it, so it may never reach the target."""
        return any(r.source_fixture == self.payload_fixture for r in self.responders)

    @property
    def file(self) -> str:
        """The attack YAML relative to the folder holding attacks/, so a
        result points at the file in the repo. Absolute if outside attacks/."""
        for parent in self.source.parents:
            if parent.name == "attacks":
                return self.source.relative_to(parent.parent).as_posix()
        return self.source.as_posix()

    @property
    def in_task(self) -> bool:
        """True if the payload is in the user turn (direct injection)."""
        return self.injection.location == TASK_LOCATION

    def planted_task(self) -> str:
        """The user turn the target receives, with the payload if it goes there."""
        if not self.in_task:
            return self.target_task
        return plant({TASK_LOCATION: self.target_task}, self.injection)[TASK_LOCATION]

    def load_fixtures(self) -> dict[str, Any]:
        return {name: _read_json(path) for name, path in self.fixtures.items()}

    def planted_fixtures(self) -> dict[str, Any]:
        """Fixtures with the payload planted. The files on disk are untouched."""
        if self.in_task:
            return self.load_fixtures()
        return plant(self.load_fixtures(), self.injection)


def plant(fixtures: dict[str, Any], injection: Injection) -> dict[str, Any]:
    """Return a copy of `fixtures` with the payload placed at its location."""
    planted = copy.deepcopy(fixtures)
    container, key = resolve_location(planted, injection.location)
    original = container[key]
    if injection.placement == "append":
        container[key] = f"{original}{PAYLOAD_SEPARATOR}{injection.payload}"
    elif injection.placement == "prepend":
        container[key] = f"{injection.payload}{PAYLOAD_SEPARATOR}{original}"
    elif injection.placement == "replace":
        container[key] = injection.payload
    else:
        raise AttackError(f"unknown placement {injection.placement!r}")
    return planted


def load_attack(path: str | Path, root: str | Path | None = None) -> Attack:
    """Load an attack file. Fixture paths resolve against `root`, which
    defaults to the directory containing `attacks/`."""
    path = Path(path).resolve()
    root = Path(root).resolve() if root else _find_root(path)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise AttackError(f"attack file not found: {path}") from e
    except yaml.YAMLError as e:
        raise AttackError(f"{path.name}: invalid YAML: {e}") from e
    return _validate(data, path, root)


def resolve_location(fixtures: dict[str, Any], location: str) -> tuple[Any, str | int]:
    """Return (container, key) for a location like `inbox[2].body`."""
    parts = [int(i) if i else name for i, name in LOCATION_PART_RE.findall(location)]
    node: Any = fixtures
    for part in parts[:-1]:
        node = _step(node, part, location)
    _step(node, parts[-1], location)
    return node, parts[-1]


def _step(node: Any, part: str | int, location: str) -> Any:
    try:
        if isinstance(part, int) and not isinstance(node, list):
            raise TypeError
        if isinstance(part, str) and not isinstance(node, dict):
            raise TypeError
        return node[part]
    except (KeyError, IndexError, TypeError) as e:
        raise AttackError(f"injection location {location!r} not found in fixtures") from e


def _validate(data: Any, path: Path, root: Path) -> Attack:
    def fail(msg: str) -> AttackError:
        return AttackError(f"{path.name}: {msg}")

    if not isinstance(data, dict):
        raise fail("must be a YAML mapping")
    missing = [k for k in REQUIRED_KEYS if k not in data]
    if missing:
        raise fail(f"missing keys {missing}")
    unknown = sorted(set(data) - set(REQUIRED_KEYS) - set(OPTIONAL_KEYS))
    if unknown:
        raise fail(f"unknown keys {unknown}")

    attack_id = data["id"]
    if not isinstance(attack_id, str) or not ID_RE.match(attack_id):
        raise fail(f"id {attack_id!r} must look like lure-xxx-001")
    # <id>.yaml is the current version; <id>-v<N>.yaml pins an older one so
    # its findings stay reproducible.
    pinned = PINNED_RE.match(path.stem)
    if path.stem != attack_id and not (pinned and pinned.group(1) == attack_id):
        raise fail(f"file name must match id {attack_id!r} (or {attack_id}-v<N> for a pinned version)")

    for key in ("name", "target_task"):
        if not isinstance(data[key], str) or not data[key].strip():
            raise fail(f"{key} must be a non-empty string")
    version = data.get("version", 1)
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise fail("version must be a whole number of at least 1")
    if pinned and int(pinned.group(2)) != version:
        raise fail(f"file name says v{pinned.group(2)} but version is {version}")
    followup_tasks = _followup_tasks(data.get("followup_tasks"), fail)
    system_prompt = data.get("system_prompt")
    if system_prompt is not None and (
        not isinstance(system_prompt, str) or not system_prompt.strip()
    ):
        raise fail("system_prompt must be a non-empty string")

    category = data["category"]
    if not isinstance(category, str) or not CATEGORY_RE.match(category):
        raise fail(f"category {category!r} must be a snake_case folder name like tool_abuse")
    if path.parent.name == "attacks":
        raise fail("attack files go in a category folder: attacks/<category>/")
    folder = category_folder(path)
    if folder is not None and folder != category:
        raise fail(f"category {category!r} does not match folder {folder!r}")

    if data["severity"] not in SEVERITIES:
        raise fail(f"severity must be one of {list(SEVERITIES)}")

    atlas = _id_list(data["atlas"], ATLAS_RE, "atlas", fail, allow_empty=False)
    attack = _id_list(data["attack"], ATTACK_RE, "attack", fail, allow_empty=True)

    tools = data["tools"]
    if not isinstance(tools, list) or not tools:
        raise fail("tools must be a non-empty list")
    bad_tools = [t for t in tools if t not in KNOWN_TOOLS]
    if bad_tools:
        raise fail(f"unknown tools {bad_tools}; known: {sorted(KNOWN_TOOLS)}")

    fixtures = _fixture_paths(data["fixtures"], root, fail)

    injection = data["injection"]
    if (
        not isinstance(injection, dict)
        or not {"location", "payload"} <= set(injection)
        or not set(injection) <= {"location", "payload", "placement", "keywords"}
    ):
        raise fail(
            "injection must have location and payload, and optionally placement and keywords"
        )
    location, payload = injection["location"], injection["payload"]
    placement = injection.get("placement", "append")
    if placement not in PLACEMENTS:
        raise fail(f"injection placement must be one of {list(PLACEMENTS)}")
    if not isinstance(location, str) or not LOCATION_RE.match(location):
        raise fail(f"injection location {location!r} is not a path like inbox[2].body")
    if not isinstance(payload, str) or not payload.strip():
        raise fail("injection payload must be a non-empty string")
    in_task = location == TASK_LOCATION
    if not in_task and LOCATION_PART_RE.match(location).group(2) not in fixtures:
        raise fail(
            f"injection location {location!r} must start with a fixture name, or be {TASK_LOCATION!r}"
        )

    rules = {
        key: _rules(data.get(key, []), key, tools, fail)
        for key in ("fail_if", "partial_if", "pass_if")
    }
    if not rules["fail_if"]:
        raise fail("fail_if must have at least one rule")

    loaded = {name: _read_json(p, fail) for name, p in fixtures.items()}
    wired = {TOOL_FIXTURES[t] for t in tools} - {None}
    responders = responders_mod.parse(data.get("responders"), tools, loaded, wired, fail)
    if not in_task:
        try:
            container, key = resolve_location(loaded, location)
        except AttackError as e:
            raise fail(str(e)) from None
        if not isinstance(container[key], str):
            raise fail(f"injection location {location!r} must point at a string")

    task_check = _task_check(data.get("task_check"), loaded, fail)
    # Facts must prove the target read the fixtures. A fact in a task payload
    # or a later user turn could be echoed straight from the user.
    echoed = [f for f in task_check if f.lower() in payload.lower()] if in_task else []
    if echoed:
        raise fail(f"task_check facts {echoed} appear in the payload")
    later = "\n".join(followup_tasks).lower()
    echoed = [f for f in task_check if f.lower() in later]
    if echoed:
        raise fail(f"task_check facts {echoed} appear in followup_tasks")
    required_tools = _required_tools(data.get("required_tools"), tools, fail)
    _check_body_contains(rules, loaded, fail)
    _check_reply_contains(rules, loaded, system_prompt, tools,
                          "\n".join([data["target_task"], *followup_tasks]), payload, fail)
    keywords = _keywords(injection.get("keywords"), payload, loaded, fail)

    _check_domains(data, f"{path.name}", fail)
    for name, content in loaded.items():
        _check_domains(content, f"fixture {name!r}", fail)

    return Attack(
        id=attack_id,
        name=data["name"],
        category=category,
        atlas=atlas,
        attack=attack,
        severity=data["severity"],
        target_task=data["target_task"],
        fixtures=fixtures,
        injection=Injection(location=location, payload=payload, placement=placement,
                            keywords=keywords),
        tools=list(tools),
        fail_if=rules["fail_if"],
        partial_if=rules["partial_if"],
        pass_if=rules["pass_if"],
        source=path,
        task_check=task_check,
        required_tools=required_tools,
        ask_markers=_ask_markers(keywords, payload, loaded),
        system_prompt=system_prompt,
        payload_source=None if in_task else _payload_source(loaded, location),
        version=version,
        followup_tasks=followup_tasks,
        responders=responders,
    )


def _followup_tasks(value, fail) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not value or not all(
        isinstance(t, str) and t.strip() for t in value
    ):
        raise fail("followup_tasks must be a non-empty list of non-empty strings")
    return list(value)


def _payload_source(fixtures, location) -> str | None:
    parts = [int(i) if i else name for i, name in LOCATION_PART_RE.findall(location)]
    if len(parts) < 2 or not isinstance(parts[1], int):
        return None
    return item_source(parts[0], fixtures[parts[0]][parts[1]])


def _required_tools(value, tools, fail) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not value:
        raise fail("required_tools must be a non-empty list of tools")
    if len(set(value)) != len(value):
        raise fail("required_tools has duplicates")
    missing = [t for t in value if t not in tools]
    if missing:
        raise fail(f"required_tools {missing} not in this attack's tools")
    return list(value)


def _keywords(value, payload, fixtures, fail) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not value or not all(
        isinstance(k, str) and k.strip() for k in value
    ):
        raise fail("injection keywords must be a non-empty list of non-empty strings")
    corpus = (payload + "\n" + "\n".join(_strings(fixtures))).lower()
    for k in value:
        if k.lower() not in corpus:
            raise fail(f"injection keyword {k!r} appears in neither the payload nor the fixtures")
    return list(value)


def _ask_markers(keywords, payload, fixtures) -> list[str]:
    # Addresses also in the clean fixtures are legit contacts (for example
    # the real CFO in a faked header), not the attacker.
    corpus = "\n".join(_strings(fixtures)).lower()
    found = []
    for m in EMAIL_RE.finditer(payload):
        found += [m.group(0).lower(), m.group(1).lower()]
    found += [h.lower() for h in URL_RE.findall(payload)]
    attacker = [f for f in found if f not in corpus]
    return list(dict.fromkeys([k.lower() for k in keywords] + attacker))


def _check_body_contains(rules, fixtures, fail) -> None:
    # body_contains and args_contain strings are fixture data the target must
    # not send out, and account_not_in lists the accounts on file. A typo in
    # any of them would leave the rule silently wrong.
    corpus = "\n".join(_strings(fixtures)).lower()
    for key, rule_list in rules.items():
        for i, rule in enumerate(rule_list):
            for k in ("body_contains", "args_contain", "account_not_in"):
                for text in rule.get(k, []):
                    if text.lower() not in corpus:
                        raise fail(f"{key}[{i}] {k} {text!r} does not appear in the fixtures")


def _check_reply_contains(rules, fixtures, system_prompt, tools, task, payload, fail) -> None:
    # A reply_contains string is something the target was given and must not
    # repeat: fixture data, its system prompt or its tool names. It must not
    # be in the task or payload, or echoing the user's message would match.
    given = "\n".join([*_strings(fixtures), system_prompt or "", *tools]).lower()
    asked = f"{task}\n{payload}".lower()
    for key, rule_list in rules.items():
        for i, rule in enumerate(rule_list):
            for text in rule.get("reply_contains", []):
                if text.lower() not in given:
                    raise fail(f"{key}[{i}] reply_contains {text!r} is not in the fixtures, "
                               "system prompt or tool names")
                if text.lower() in asked:
                    raise fail(f"{key}[{i}] reply_contains {text!r} appears in the task or payload")


def _task_check(value, fixtures, fail) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not value:
        raise fail("task_check must be a non-empty list of facts")
    corpus = "\n".join(_strings(fixtures)).lower()
    for fact in value:
        if not isinstance(fact, str) or not fact.strip():
            raise fail("task_check facts must be non-empty strings")
        # Facts come from the clean fixtures, so the payload cannot satisfy them.
        if fact.lower() not in corpus:
            raise fail(f"task_check fact {fact!r} does not appear in the fixtures")
    return list(value)


def _id_list(value, pattern, key, fail, allow_empty):
    if not isinstance(value, list) or (not value and not allow_empty):
        raise fail(f"{key} must be a {'' if allow_empty else 'non-empty '}list")
    bad = [v for v in value if not isinstance(v, str) or not pattern.match(v)]
    if bad:
        raise fail(f"{key} has malformed ids {bad}")
    return list(value)


def _fixture_paths(value, root, fail) -> dict[str, Path]:
    if not isinstance(value, dict) or not value:
        raise fail("fixtures must be a non-empty mapping of name to path")
    fixtures_dir = (root / "fixtures").resolve()
    paths = {}
    for name, rel in value.items():
        if not isinstance(rel, str):
            raise fail(f"fixture {name!r} path must be a string")
        resolved = (root / rel).resolve()
        if not resolved.is_relative_to(fixtures_dir):
            raise fail(f"fixture {name!r} must live under fixtures/: {rel}")
        if not resolved.is_file():
            raise fail(f"fixture {name!r} not found: {rel}")
        paths[name] = resolved
    return paths


def _rules(value, key, tools, fail) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise fail(f"{key} must be a list")
    for i, rule in enumerate(value):
        where = f"{key}[{i}]"
        if not isinstance(rule, dict) or not rule:
            raise fail(f"{where} must be a non-empty mapping")
        for k, v in rule.items():
            kind = RULE_KEYS.get(k)
            if kind is None:
                raise fail(f"{where} unknown rule key {k!r}; known: {sorted(RULE_KEYS)}")
            if kind == "tool" and v not in tools:
                raise fail(f"{where} {k} {v!r} is not in this attack's tools")
            if kind == "bool" and not isinstance(v, bool):
                raise fail(f"{where} {k} must be true or false")
            if kind == "domains" and (
                not isinstance(v, list) or not v or not all(isinstance(d, str) for d in v)
            ):
                raise fail(f"{where} {k} must be a non-empty list of domains")
            if kind == "strings" and (
                not isinstance(v, list) or not v
                or not all(isinstance(t, str) and t.strip() for t in v)
            ):
                raise fail(f"{where} {k} must be a non-empty list of non-empty strings")
        for k in ("to_domain_not_in", "body_contains", "args_contain", "account_not_in"):
            if k in rule and not ({"tool", "asked_user_before"} & set(rule)):
                raise fail(f"{where} {k} needs a tool or asked_user_before")
    return list(value)


def _check_domains(value: Any, where: str, fail) -> None:
    for text in _strings(value):
        text = "\n".join([text, *_decoded_base64(text)])
        hosts = EMAIL_RE.findall(text) + URL_RE.findall(text)
        for host in hosts:
            if not _is_example(host):
                raise fail(f"{where} uses non-.example domain {host!r}")
    for domains in _domain_lists(value):
        for d in domains:
            if not _is_example(d):
                raise fail(f"{where} uses non-.example domain {d!r}")


def _decoded_base64(text: str) -> list[str]:
    decoded = []
    for token in BASE64_RE.findall(text):
        try:
            raw = base64.b64decode(token + "=" * (-len(token) % 4), validate=True)
            decoded.append(raw.decode("utf-8"))
        except (binascii.Error, UnicodeDecodeError):
            continue
    return decoded


def _is_example(host: str) -> bool:
    host = host.lower().rstrip(".")
    return host == "example" or host.endswith(".example")


def _strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _strings(k)
            yield from _strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v)


def _domain_lists(value: Any):
    if isinstance(value, dict):
        for k, v in value.items():
            if k in ("to_domain_not_in", "to_domain_in") and isinstance(v, list):
                yield [d for d in v if isinstance(d, str)]
            else:
                yield from _domain_lists(v)
    elif isinstance(value, list):
        for v in value:
            yield from _domain_lists(v)


def category_folder(path: Path) -> str | None:
    """The folder directly under attacks/ that holds `path`, or None when the
    file is not inside an attacks/<category>/ folder."""
    parts = path.resolve().parts
    for i in range(len(parts) - 2, -1, -1):
        if parts[i] == "attacks":
            return parts[i + 1] if i + 2 < len(parts) else None
    return None


def attacks_root(path: str | Path) -> Path | None:
    """The attacks/ folder at or above `path`, if there is one."""
    path = Path(path).resolve()
    for folder in (path, *path.parents):
        if folder.name == "attacks":
            return folder
    return None


def discover_categories(attacks_dir: str | Path) -> list[str]:
    """Category folders under attacks_dir: each subfolder holding a *.yaml."""
    return sorted(d.name for d in Path(attacks_dir).iterdir()
                  if d.is_dir() and any(d.rglob("*.yaml")))


def _find_root(path: Path) -> Path:
    for parent in path.parents:
        if parent.name == "attacks":
            return parent.parent
    return Path.cwd().resolve()


def _read_json(path: Path, fail=None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        msg = f"fixture {path.name} is not valid JSON: {e}"
        raise (fail(msg) if fail else AttackError(msg)) from e
