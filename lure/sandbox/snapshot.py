"""lure sandbox mcp-snapshot: the approved MCP servers' tool definitions,
fetched from inside the sandbox.

The operator-exported snapshot (a profile's mcp_tools_snapshot) is the
default way to give Lure a server's tool definitions. This is the optional
other way, for remote servers only: the reference agent image's
standard-library client (refagent/mcpsnap.py) calls initialize and
tools/list through the gateway, which allows the approved servers' hosts
and nothing else. No tool is called, no model is called, no key goes in.
Local (stdio) servers are never started by Lure: export their snapshot.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from lure.sandbox.docker import Sandbox, SandboxSpec

CLIENT = ("/usr/local/bin/python3", "/opt/lure/mcpsnap.py")


def fetch_snapshot(servers: list[tuple[str, str]], agent_image: str, gateway_image: str,
                   allow: tuple[str, ...],
                   sandbox_factory: Callable[[SandboxSpec], Sandbox] = Sandbox,
                   spec_extra: dict[str, Any] | None = None) -> tuple[dict[str, Any], list]:
    """{name: {"tools": [...]}} for each (name, url), and the gateway's
    egress decisions (for the record: only approved hosts are reached)."""
    spec = SandboxSpec(agent_image, gateway_image, allow, **(spec_extra or {}))
    with sandbox_factory(spec) as sbx:
        done = sbx.exec(list(CLIENT), input=json.dumps(
            [{"name": n, "url": u} for n, u in servers]).encode(), timeout=300)
        events = sbx.gateway_events()
    try:
        out = json.loads(done.stdout or b"{}")
    except ValueError:
        out = {n: {"error": "the snapshot client gave no answer"} for n, _ in servers}
    return out, [e for e in events if e.get("event") == "egress"]
