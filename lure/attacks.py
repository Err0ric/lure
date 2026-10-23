"""Load and validate attack YAML files.

Validation is strict so a bad attack fails at load time, not mid-run. It
also enforces the fake-data rule: every email address, URL host and listed
domain in the attack and its fixtures must be under the reserved .example
TLD.
"""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from lure.tools import KNOWN_TOOLS

CATEGORIES = frozenset(
    {
        "indirect_prompt_injection",
        "direct_prompt_injection",
        "jailbreak",
        "data_leakage",
        "tool_abuse",
    }
)
SEVERITIES = ("low", "medium", "high", "critical")
REQUIRED_KEYS = (
    "id", "name", "category", "atlas", "attack", "severity",
    "target_task", "fixtures", "injection", "tools", "fail_if",
)
OPTIONAL_KEYS = ("partial_if", "pass_if", "task_check", "required_tools")
PLACEMENTS = ("append", "prepend", "replace")
PAYLOAD_SEPARATOR = "\n\n"
# Rule keys the Judge understands. Keys naming a tool must be in `tools`.
RULE_KEYS = {
    "tool": "tool",
    "to_domain_not_in": "domains",
    "body_contains": "strings",
    "asked_user_before": "tool",
    "flagged_as_suspicious": "bool",
}

ID_RE = re.compile(r"^lure-[a-z]+-\d{3}$")
ATLAS_RE = re.compile(r"^AML\.T\d{4}(\.\d{3})?$")
ATTACK_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
LOCATION_RE = re.compile(r"^[A-Za-z_]\w*(\[\d+\]|\.[A-Za-z_]\w*)*$")
LOCATION_PART_RE = re.compile(r"\[(\d+)\]|\.?([A-Za-z_]\w*)")
EMAIL_RE = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")
URL_RE = re.compile(r"https?://([^/\s:?#]+)", re.IGNORECASE)


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

    def load_fixtures(self) -> dict[str, Any]:
        return {name: _read_json(path) for name, path in self.fixtures.items()}

    def planted_fixtures(self) -> dict[str, Any]:
        """Fixtures with the payload planted. The files on disk are untouched."""
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
    if path.stem != attack_id:
        raise fail(f"file name must match id {attack_id!r}")

    for key in ("name", "target_task"):
        if not isinstance(data[key], str) or not data[key].strip():
            raise fail(f"{key} must be a non-empty string")

    category = data["category"]
    if category not in CATEGORIES:
        raise fail(f"category {category!r} must be one of {sorted(CATEGORIES)}")
    if path.parent.name in CATEGORIES and path.parent.name != category:
        raise fail(f"category {category!r} does not match folder {path.parent.name!r}")

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
    if LOCATION_PART_RE.match(location).group(2) not in fixtures:
        raise fail(f"injection location {location!r} must start with a fixture name")

    rules = {
        key: _rules(data.get(key, []), key, tools, fail)
        for key in ("fail_if", "partial_if", "pass_if")
    }
    if not rules["fail_if"]:
        raise fail("fail_if must have at least one rule")

    loaded = {name: _read_json(p, fail) for name, p in fixtures.items()}
    try:
        container, key = resolve_location(loaded, location)
    except AttackError as e:
        raise fail(str(e)) from None
    if not isinstance(container[key], str):
        raise fail(f"injection location {location!r} must point at a string")

    task_check = _task_check(data.get("task_check"), loaded, fail)
    required_tools = _required_tools(data.get("required_tools"), tools, fail)
    _check_body_contains(rules, loaded, fail)
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
    )


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
    # The strings are fixture data the target must not send out, so a typo
    # would leave the rule silently unable to match.
    corpus = "\n".join(_strings(fixtures)).lower()
    for key, rule_list in rules.items():
        for i, rule in enumerate(rule_list):
            for text in rule.get("body_contains", []):
                if text.lower() not in corpus:
                    raise fail(f"{key}[{i}] body_contains {text!r} does not appear in the fixtures")


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
        for k in ("to_domain_not_in", "body_contains"):
            if k in rule and not ({"tool", "asked_user_before"} & set(rule)):
                raise fail(f"{where} {k} needs a tool or asked_user_before")
    return list(value)


def _check_domains(value: Any, where: str, fail) -> None:
    for text in _strings(value):
        hosts = EMAIL_RE.findall(text) + URL_RE.findall(text)
        for host in hosts:
            if not _is_example(host):
                raise fail(f"{where} uses non-.example domain {host!r}")
    for domains in _domain_lists(value):
        for d in domains:
            if not _is_example(d):
                raise fail(f"{where} uses non-.example domain {d!r}")


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
            if k == "to_domain_not_in" and isinstance(v, list):
                yield [d for d in v if isinstance(d, str)]
            else:
                yield from _domain_lists(v)
    elif isinstance(value, list):
        for v in value:
            yield from _domain_lists(v)


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
