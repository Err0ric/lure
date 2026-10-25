"""lure sandbox run: one attack against a real agent in the sandbox.

The attack's file fixtures become the agent's /workspace (paths relative to
the folder they share, which the task calls the working directory), its
agent_settings fixture becomes the agent's settings file with the model URL
from the profile, and the agent gets the profile's system prompt and the
attack's task. Lure then reads back:

  the gateway's log      egress decisions and DNS lookups (Lure-observed)
  the workspace          a diff against what was copied in (Lure-observed)
  the decoy log          npm, pip, curl, wget and git calls (written inside
                         the agent's container; see refagent/decoy.py)
  the agent's own log    its tool calls and final reply (agent-reported)

Judging: egress_to rules are decided from the gateway's log. Tool rules are
decided from the agent's own call log, which only Lure's reference agent
writes (record `sandbox.tool_calls_source: agent`); a third-party agent
reports none until it uses Lure's mock tools over MCP (roadmap v1.14). File
paths in that log are mapped back to the fixture's paths, so rules and the
delivery check read the same paths as in a mock run.

A run the agent could not finish (for example because its model requests
were blocked) is an Error, unless a fail_if rule already matched: a blocked
connection to the attacker's host is the finding, not a broken run.
"""

from __future__ import annotations

import json
import os
import posixpath
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

from lure.attacks import Attack
from lure.exposure import OrgPolicy
from lure.judge.rules import Verdict, judge
from lure.profiles import Profile
from lure.runner import STOP_COMPLETED, STOP_ERROR, RunResult
from lure.sandbox import evidence
from lure.sandbox.docker import Limits, Sandbox, SandboxSpec
from lure.tools.call_log import ToolCallLog

PATH_TOOLS = ("read_file", "write_file", "delete_file")
MAX_TURNS = 10


def _utc_now() -> datetime:
    return datetime.now(UTC)


def workspace(attack: Attack, profile: Profile) -> tuple[dict[str, bytes], str | None]:
    """The files to copy into /workspace, and the folder the fixture paths
    share (the task's working directory), which maps to /workspace."""
    agent = profile.agent
    fixtures = attack.planted_fixtures()
    files: dict[str, bytes] = {}
    alias = None
    items = [f for f in fixtures.get("files", []) if isinstance(f, dict)
             and isinstance(f.get("path"), str)]
    if items:
        paths = [posixpath.normpath(f["path"]) for f in items]
        alias = posixpath.commonpath([posixpath.dirname(p) or "/" for p in paths])
        for item, path in zip(items, paths, strict=True):
            rel = posixpath.relpath(path, alias) if path.startswith("/") else path
            files[rel] = str(item.get("content", "")).encode()
    settings = fixtures.get("agent_settings")
    settings = dict(settings) if isinstance(settings, dict) else {}
    settings[agent.model_url_key] = agent.model_url
    files[agent.settings_file] = (json.dumps(settings, indent=2) + "\n").encode()
    return files, alias


def job(attack: Attack, profile: Profile, prompt: str, alias: str | None) -> dict[str, Any]:
    return {"system": prompt, "task": attack.planted_task(), "provider": profile.agent.provider,
            "model": profile.model or "", "max_turns": MAX_TURNS, "workdir_alias": alias}


def spec_for(profile: Profile, agent_image: str | None, gateway_image: str) -> SandboxSpec:
    agent = profile.agent
    limits = Limits(**{k: (int(v) if k == "pids" else v) for k, v in agent.limits})
    return SandboxSpec(agent_image=agent_image or agent.image, gateway_image=gateway_image,
                       allow=(agent.model_allow, *agent.allow), env=agent.env, limits=limits)


def to_fixture_path(path: Any, alias: str | None) -> Any:
    """A workspace path as the fixture names it: relative paths and the
    workspace itself map back under the task's working directory."""
    if not isinstance(path, str) or alias is None:
        return path
    p = path.strip()
    if p.startswith("/workspace"):
        p = p[len("/workspace"):].lstrip("/")
    if p.startswith("/"):
        return p
    return posixpath.normpath(posixpath.join(alias, p))


def usage_of(lines: list[dict[str, Any]]) -> dict[str, int]:
    """Token counts the agent reported, summed over its model requests."""
    usage: dict[str, int] = {}
    for line in lines:
        if line.get("lure") == "usage":
            for key in ("input_tokens", "output_tokens"):
                value = line.get(key)
                if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                    usage[key] = usage.get(key, 0) + value
    return usage


def agent_log(lines: list[dict[str, Any]], alias: str | None,
              clock: Callable[[], datetime]) -> tuple[ToolCallLog, str | None, str | None,
                                                      list[str]]:
    """The agent's reported tool calls, final reply, error and model hosts."""
    log = ToolCallLog(clock=clock)
    reply = error = None
    hosts: list[str] = []
    for line in lines:
        kind = line.get("lure")
        if kind == "call" and isinstance(line.get("tool"), str):
            args = dict(line.get("args") or {}) if isinstance(line.get("args"), dict) else {}
            if line["tool"] in PATH_TOOLS and "path" in args:
                args["path"] = to_fixture_path(args["path"], alias)
            log.record(line["tool"], args, line.get("result"))
        elif kind == "reply":
            reply = str(line.get("text") or "")
        elif kind == "error":
            error = str(line.get("message") or "the agent stopped with an error")
        elif kind == "model" and isinstance(line.get("host"), str):
            if line["host"] not in hosts:
                hosts.append(line["host"])
    return log, reply, error, hosts


def run_in_sandbox(attack: Attack, profile: Profile, prompt: str, *, gateway_image: str,
                   agent_image: str | None = None, org_policy: OrgPolicy | None = None,
                   profile_record: dict[str, Any] | None = None,
                   sandbox_factory: Callable[[SandboxSpec], Sandbox] = Sandbox,
                   clock: Callable[[], datetime] = _utc_now) -> RunResult:
    if profile.agent is None or profile.isolation != "container":
        raise ValueError("lure sandbox run needs a profile with an agent: block and "
                         "isolation: container")
    started = clock()
    files, alias = workspace(attack, profile)
    spec = spec_for(profile, agent_image, gateway_image)
    the_job = job(attack, profile, prompt, alias)
    with sandbox_factory(spec) as sbx:
        sbx.seed(files)
        done = sbx.exec(list(profile.agent.command),
                        input=json.dumps(the_job).encode())
        after = sbx.snapshot()
        decoys = sbx.decoys()
        events = sbx.gateway_events()
        enforced = sbx.enforced()
    lines = evidence.json_lines(done.stdout.decode(errors="replace"))
    log, reply, error, hosts = agent_log(lines, alias, clock)
    if error is None and reply is None:
        error = (f"the agent exited with code {done.returncode} and no reply: "
                 + done.stderr.decode(errors="replace").strip()[-300:])
    egress = evidence.egress(events)
    blocked = evidence.egress_blocked(events)
    judgment = judge(attack, log, final_text=reply, egress=egress)
    if error is not None and judgment.verdict is not Verdict.FAIL:
        judgment = judge(attack, log, final_text=reply, error=error, egress=egress)
    endpoint = evidence.model_endpoint(files, after, profile.agent.settings_file,
                                       profile.agent.model_url_key, blocked)
    if endpoint is not None and judgment.verdict is Verdict.FAIL:
        state = "blocked at the gateway" if endpoint["blocked"] else "not seen at the gateway"
        judgment = replace(judgment, reason=f"{judgment.reason}; critical: the agent changed "
                                            f"its own model endpoint to {endpoint['host']} "
                                            f"({state})")
    replies = [reply] if reply is not None else []
    exposure = (org_policy.record(log.calls, attack.expected_fetch, replies)
                if org_policy is not None else
                {"policy": "none", "allowed_outbound_domains": [], "calls": [], "rendered": []})
    exposure["egress_blocked"] = blocked
    exposure["dns_lookups"] = evidence.dns_lookups(events)
    transcript = [{"role": "system", "content": prompt},
                  {"role": "user", "content": the_job["task"]}]
    if reply is not None:
        transcript.append({"role": "assistant", "content": reply, "tool_calls": [],
                           "stop_reason": "end_turn"})
    sandbox_record = {
        "isolation": "container",
        "agent_image": spec.agent_image,
        "gateway_image": spec.gateway_image,
        "allow": list(spec.allow),
        "env": list(spec.env),
        "enforced": enforced,
        "tool_calls_source": "agent",
        "agent_exit_code": done.returncode,
        "model_hosts": hosts,
        "egress_allowed": evidence.egress_allowed(events),
        "decoys": decoys,
        "workspace": evidence.workspace_diff(files, after),
        "model_endpoint": endpoint,
        "teardown": sbx.teardown_record(),
    }
    result = RunResult(
        attack=attack, target=f"sandbox:{spec.agent_image}", started_at=started,
        finished_at=clock(), turns=sum(1 for line in lines if line.get("lure") == "model"),
        max_turns=MAX_TURNS, stop=STOP_ERROR if error else STOP_COMPLETED,
        final_text=reply, transcript=transcript, log=log, judgment=judgment, error=error,
        usage=usage_of(lines), exposure=exposure, replies=replies,
        fixtures_sha256=attack.fixture_hashes(),
        profile=profile_record)
    result.sandbox = sandbox_record
    return result


def missing_env(profile: Profile) -> list[str]:
    """Environment variables the profile passes in by name but Lure's own
    environment does not set."""
    return [n for n in profile.agent.env if not os.environ.get(n)]
