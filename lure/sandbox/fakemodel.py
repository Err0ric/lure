"""A scripted model server for the sandbox's integration tests.

Speaks just enough of the Anthropic Messages API (POST /v1/messages) for
the reference agent: each request gets the next scripted response, and
after the script ends a plain text reply. It runs in Lure's own image on
the gateway's outside network, so the tests prove the allowed model host
is reachable through the proxy without calling a real model API.

With --echo-port it also listens there for raw TCP and answers any bytes
with ECHO_REPLY, so the TLS passthrough (SNI) test can see a ClientHello
arrive without a real TLS server.

Every request is one JSON line on stdout.
"""

from __future__ import annotations

import argparse
import base64
import json
import socket
import socketserver
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

ECHO_REPLY = b"LURE-ECHO\n"
DONE = {"content": [{"type": "text", "text": "Done."}], "stop_reason": "end_turn"}
MCP_TOOLS = [
    {"name": "lookup_customer", "description": "Look up a customer by id.",
     "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}}},
    {"name": "list_orders", "description": "List a customer's orders.",
     "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}}},
]


def log(event: dict[str, Any]) -> None:
    print(json.dumps(event, sort_keys=True), file=sys.stdout, flush=True)


def make_handler(script: list[dict[str, Any]]):
    lock = threading.Lock()
    state = {"n": 0}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args) -> None:
            pass

        def _reply(self, code: int, body: dict[str, Any]) -> None:
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _mcp(self, body: dict[str, Any]) -> None:
            """A stand-in MCP server (Streamable HTTP): initialize and
            tools/list only, two pages, the second as an event stream."""
            log({"event": "mcp", "method": body.get("method"),
                 "session": self.headers.get("mcp-session-id")})
            if "id" not in body:
                self.send_response(202)
                self.end_headers()
                return
            if body["method"] == "initialize":
                result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                          "serverInfo": {"name": "lure-fake-mcp", "version": "1"}}
            elif body["method"] == "tools/list" and not (body.get("params") or {}).get("cursor"):
                result = {"tools": [MCP_TOOLS[0]], "nextCursor": "page2"}
            elif body["method"] == "tools/list":
                data = json.dumps({"jsonrpc": "2.0", "id": body["id"],
                                   "result": {"tools": MCP_TOOLS[1:]}})
                raw = f"event: message\ndata: {data}\n\n".encode()
                self.send_response(200)
                self.send_header("content-type", "text/event-stream")
                self.send_header("content-length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
                return
            else:
                result = None
            data = json.dumps({"jsonrpc": "2.0", "id": body["id"], **(
                {"result": result} if result is not None else
                {"error": {"code": -32601, "message": "method not found"}})}).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("mcp-session-id", "lure-test-session")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:
            log({"event": "request", "method": "GET", "path": self.path,
                 "host": self.headers.get("host")})
            self._reply(200, {"ok": True, "server": "lure-fake-model"})

        def do_POST(self) -> None:
            n = int(self.headers.get("content-length") or 0)
            body = json.loads(self.rfile.read(n) or b"{}")
            if self.path.startswith("/mcp"):
                self._mcp(body)
                return
            with lock:
                i = state["n"]
                state["n"] += 1
            log({"event": "request", "method": "POST", "path": self.path, "n": i,
                 "host": self.headers.get("host"),
                 "has_key": bool(self.headers.get("x-api-key")),
                 "messages": len(body.get("messages", []))})
            step = script[i] if i < len(script) else DONE
            self._reply(200, {"id": f"msg-{i}", "type": "message", "role": "assistant",
                              "model": body.get("model"), **step})

    return Handler


class Echo(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(10)
        try:
            data = self.request.recv(65536)
        except OSError:
            return
        log({"event": "echo", "bytes": len(data)})
        self.request.sendall(ECHO_REPLY)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m lure.sandbox.fakemodel")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--script", default="",
                        help="base64 of a JSON list of responses ({content, stop_reason})")
    parser.add_argument("--echo-port", type=int)
    args = parser.parse_args(argv)
    script = json.loads(base64.b64decode(args.script)) if args.script else []
    if args.echo_port:
        class EchoServer(socketserver.ThreadingTCPServer):
            daemon_threads = True
            allow_reuse_address = True
            address_family = socket.AF_INET

        echo = EchoServer(("0.0.0.0", args.echo_port), Echo)
        threading.Thread(target=echo.serve_forever, daemon=True).start()
    server = ThreadingHTTPServer(("0.0.0.0", args.port), make_handler(script))
    log({"event": "ready", "port": args.port, "echo_port": args.echo_port,
         "steps": len(script)})
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
