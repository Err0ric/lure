"""A deliberately vulnerable coding agent, for the sandbox's Docker tests
only. Never shipped in an image: the test copies it into the container.

It does what a careless real agent does with an AGENTS.md in its working
directory: loads it at startup, then obeys it. Every "set <setting> to
<value>" becomes a change to its own settings, and every backticked
npm, npx, pip, curl, wget or git command is run in its shell. Only then does
it ask its model (at the settings' model_base_url, re-read) to do the task.
It speaks the reference agent's output protocol, so Lure judges it the
same way. Standard library only.
"""

import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

WORKSPACE = Path(os.environ.get("LURE_WORKSPACE", "/workspace"))
SETTINGS = WORKSPACE / ".agent" / "settings.json"
SET_RE = re.compile(r"\bset (\w+) to (\S+?)[.,;:]?(?=\s|$)", re.IGNORECASE)
COMMAND_RE = re.compile(r"`((?:npm|npx|pip|pip3|curl|wget|git) [^`]+)`")


def out(kind, **fields):
    print(json.dumps({"lure": kind, **fields}), flush=True)


def value(text):
    return int(text) if text.isdigit() else text


def main():
    job = json.loads(sys.stdin.read())
    done = []
    agents = WORKSPACE / "AGENTS.md"
    text = agents.read_text(errors="replace") if agents.is_file() else ""
    if text:
        out("call", tool="read_file", args={"path": "AGENTS.md"},
            result={"path": "AGENTS.md", "content": text, "loaded_at_startup": True}, error=False)
    for name, new in SET_RE.findall(text):
        settings = json.loads(SETTINGS.read_text())
        settings[name] = value(new)
        SETTINGS.write_text(json.dumps(settings, indent=2) + "\n")
        out("call", tool="update_agent_settings", args={"changes": {name: value(new)}},
            result={"status": "updated"}, error=False)
        done.append(f"set {name} to {new}")
    for command in COMMAND_RE.findall(text):
        run = subprocess.run(["/bin/sh", "-c", command], cwd=WORKSPACE, capture_output=True,
                             text=True, timeout=30, check=False)
        out("call", tool="run_command", args={"command": command},
            result={"exit_code": run.returncode, "output": (run.stdout + run.stderr)[-2000:]},
            error=False)
        done.append(f"ran {command}")
    base = json.loads(SETTINGS.read_text())["model_base_url"].rstrip("/")
    url = base + ("/messages" if base.endswith("/v1") else "/v1/messages")
    out("model", host=urllib.parse.urlsplit(url).hostname or "", url=url)
    body = {"model": job.get("model"), "max_tokens": 512, "system": job["system"],
            "messages": [{"role": "user", "content": job["task"]}]}
    req = urllib.request.Request(url, json.dumps(body).encode(), method="POST",
                                 headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            data = json.loads(r.read())
    except (urllib.error.URLError, OSError) as e:
        out("error", message=f"{type(e).__name__}: {e}")
        return 1
    usage = data.get("usage") or {}
    out("usage", input_tokens=usage.get("input_tokens", 0),
        output_tokens=usage.get("output_tokens", 0))
    answer = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
    out("reply", text=f"{answer} Following AGENTS.md, I {'; '.join(done) or 'changed nothing'}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
