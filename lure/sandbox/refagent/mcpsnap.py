#!/usr/local/bin/python3
"""Fetch MCP tool definitions (tools/list) from remote servers, inside the
sandbox. Standard library only.

Reads a JSON list of {"name", "url"} on stdin and writes
{name: {"tools": [...]}} (or {name: {"error": ...}}) on stdout. Speaks the
Streamable HTTP transport: initialize, notifications/initialized, then
tools/list until there is no nextCursor; a response may be JSON or a
text/event-stream. Only the gateway is reachable, and it allows only the
approved servers' hosts. No tool is ever called.
"""

import json
import sys
import urllib.error
import urllib.request

PROTOCOL = "2025-06-18"
TIMEOUT = 30
MAX_PAGES = 20


def rpc(url, body, session=None):
    headers = {"content-type": "application/json",
               "accept": "application/json, text/event-stream",
               "mcp-protocol-version": PROTOCOL}
    if session:
        headers["mcp-session-id"] = session
    req = urllib.request.Request(url, json.dumps(body).encode(), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        session = r.headers.get("mcp-session-id") or session
        raw = r.read().decode("utf-8", "replace")
        kind = r.headers.get("content-type", "")
    if "id" not in body:
        return None, session
    if "text/event-stream" in kind:
        for line in raw.splitlines():
            if line.startswith("data:"):
                msg = json.loads(line[5:].strip())
                if msg.get("id") == body["id"]:
                    return msg, session
        raise ValueError("no response in the event stream")
    return json.loads(raw), session


def tools(url):
    init, session = rpc(url, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": PROTOCOL, "capabilities": {},
        "clientInfo": {"name": "lure-mcp-snapshot", "version": "1"}}})
    if "error" in init:
        raise ValueError(f"initialize failed: {init['error']}")
    rpc(url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, session)
    found, cursor = [], None
    for n in range(MAX_PAGES):
        params = {"cursor": cursor} if cursor else {}
        msg, session = rpc(url, {"jsonrpc": "2.0", "id": 2 + n, "method": "tools/list",
                                 "params": params}, session)
        if "error" in msg:
            raise ValueError(f"tools/list failed: {msg['error']}")
        result = msg.get("result") or {}
        found += result.get("tools") or []
        cursor = result.get("nextCursor")
        if not cursor:
            break
    return found


def main():
    out = {}
    for server in json.loads(sys.stdin.read()):
        try:
            out[server["name"]] = {"tools": tools(server["url"])}
        except (urllib.error.URLError, OSError, ValueError, KeyError) as e:
            out[server["name"]] = {"error": f"{type(e).__name__}: {e}"}
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
