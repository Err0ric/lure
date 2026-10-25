"""MCP servers in an agent's config: what they are, whether they are pinned,
whether the organization approved them, and their tool definitions' hash.

Configs read: the "mcpServers" mapping (Claude Desktop, Claude Code, Cursor
and others) and VS Code's "servers", in JSON or YAML. A server is remote
(url) or local (command and args, such as npx -y @scope/server@1.2.3).
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from lure.policy import PINNED_PACKAGE_RE, McpPolicy

RUNNERS = {"npx", "bunx", "pnpx", "uvx", "pipx", "docker", "deno"}
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
# A package argument: not a flag, and shaped like a package name.
PACKAGE_RE = re.compile(r"^(?:@[\w.-]+/)?[\w.-]+(?:@[^\s]+|==[^\s]+)?$")


@dataclass(frozen=True)
class Server:
    name: str
    source: str
    url: str | None = None
    command: str | None = None
    package: str | None = None

    @property
    def remote(self) -> bool:
        return self.url is not None

    @property
    def host(self) -> str | None:
        if self.url is None:
            return None
        parts = urlsplit(self.url)
        port = parts.port or (443 if parts.scheme == "https" else 80)
        return f"{(parts.hostname or '').lower()}:{port}"

    @property
    def pinned(self) -> bool:
        return self.remote or bool(self.package and PINNED_PACKAGE_RE.match(self.package))


def load_config(path: Path) -> Any:
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        return json.loads(text)
    except ValueError:
        try:
            return yaml.safe_load(text)
        except yaml.YAMLError:
            return None


def servers(path: Path) -> list[Server]:
    data = load_config(path)
    if not isinstance(data, dict):
        return []
    found = []
    for key in ("mcpServers", "servers"):
        block = data.get(key)
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            if isinstance(spec, dict):
                found.append(_server(str(name), spec, str(path)))
    return found


def _server(name: str, spec: dict[str, Any], source: str) -> Server:
    url = spec.get("url") or spec.get("serverUrl")
    if isinstance(url, str) and url:
        return Server(name, source, url=url)
    command = spec.get("command")
    args = [str(a) for a in spec.get("args") or [] if isinstance(a, (str, int, float))]
    package = None
    if isinstance(command, str) and Path(command).name in RUNNERS:
        package = next((a for a in args if not a.startswith("-") and PACKAGE_RE.match(a)), None)
    return Server(name, source, command=command if isinstance(command, str) else None,
                  package=package)


def unpinned_reason(server: Server) -> str | None:
    if server.remote or server.package is None:
        return None
    if server.package.endswith("@latest"):
        return f"runs {server.package}, whatever version is newest"
    if not PINNED_PACKAGE_RE.match(server.package):
        return f"runs {server.package} with no exact version"
    return None


def allowlist_problem(server: Server, policy: McpPolicy) -> str | None:
    """Why the server is not approved, or None."""
    approved = policy.get(server.name)
    if approved is None:
        return f"{server.name} is not on the approved list"
    if approved.url is not None:
        if not server.remote:
            return f"{server.name} is approved as a remote server, but runs locally here"
        if server.host != approved.host:
            return f"{server.name} points at {server.host}, not the approved {approved.host}"
        return None
    if server.remote:
        return f"{server.name} is approved as a local package, but is remote here"
    if server.package != approved.package:
        if server.package and not PINNED_PACKAGE_RE.match(server.package):
            return f"{server.name} runs {server.package} with no exact version"
        return f"{server.name} runs {server.package}, not the approved {approved.package}"
    return None


def tool_hashes(snapshot: Path) -> dict[str, str]:
    """server name -> SHA-256 of its tool definitions (name, description,
    input schema; sorted, canonical JSON). The snapshot maps each server to
    its tools/list result or its tools."""
    data = load_config(snapshot)
    out = {}
    for name, value in (data or {}).items() if isinstance(data, dict) else ():
        tools = value.get("tools", value) if isinstance(value, dict) else value
        if not isinstance(tools, list):
            continue
        canon = sorted(({"name": t.get("name"), "description": t.get("description"),
                         "inputSchema": t.get("inputSchema", t.get("input_schema"))}
                        for t in tools if isinstance(t, dict)), key=lambda t: str(t["name"]))
        out[str(name)] = hashlib.sha256(json.dumps(canon, sort_keys=True,
                                                   separators=(",", ":")).encode()).hexdigest()
    return out


def snapshot_descriptions(snapshot: Path) -> list[tuple[str, str]]:
    """(server/tool, description) from a snapshot, for check 7."""
    data = load_config(snapshot)
    found = []
    for name, value in (data or {}).items() if isinstance(data, dict) else ():
        tools = value.get("tools", value) if isinstance(value, dict) else value
        for t in tools if isinstance(tools, list) else []:
            if isinstance(t, dict) and isinstance(t.get("description"), str):
                found.append((f"{name}/{t.get('name')}", t["description"]))
    return found
