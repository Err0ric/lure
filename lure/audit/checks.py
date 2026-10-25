"""lure audit: a static pre-flight check of an agent's setup.

Reads the profile and the files it names (prompt file, agent config such as
mcp.json, settings and a workspace .env, an MCP tool snapshot) and the
policy. No model call, no network. Runs on its own (lure audit) and before
any model call of lure run --profile, lure retest and lure sandbox run.

Critical findings (credentials, acting without asking, a foreign model
endpoint, an MCP server off the approved list) stop the run. High and
medium findings are reported and the run goes on. Info findings are
reported only and never change a decision. No finding holds a secret:
see lure.audit.findings.
"""

from __future__ import annotations

import ipaddress
import os
import re
from collections.abc import Iterable
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlsplit

from lure.audit import mcp
from lure.audit.findings import (
    CHECKS,
    CRITICAL,
    HIGH,
    INFO,
    MEDIUM,
    AuditResult,
    Finding,
    salt,
)
from lure.audit.secrets import gitleaks_version, scan
from lure.policy import Policy
from lure.profiles import AGENT_KEY, Profile

# Check 2: settings that mean "act without asking", by normalized name
# (lowercase, no _ - or spaces). Values: what turns it on; "*" any truthy.
AUTO_APPROVE_KEYS: dict[str, tuple[str, ...]] = {
    "defaultmode": ("bypasspermissions", "dontask", "auto", "yolo"),
    "permissionmode": ("bypasspermissions", "dontask", "auto", "yolo"),
    "approvalpolicy": ("never",),
    "askforapproval": ("never",),
    "autoapprove": ("*",),
    "autoapprovecommands": ("*",),
    "autoapprovetools": ("*",),
    "alwaysallow": ("*",),
    "skippermissions": ("*",),
    "skippermissionprompts": ("*",),
    "dangerouslyskippermissions": ("*",),
    "yolo": ("*",),
    "fullauto": ("*",),
    "autorun": ("*",),
    "autoexecute": ("*",),
    "trustalltools": ("*",),
    "requireconfirmation": ("false",),
    "confirmactions": ("false",),
}
AUTO_APPROVE_FLAGS = ("--dangerously-skip-permissions", "--dangerously-bypass-approvals-and-sandbox",
                      "--yolo", "--full-auto", "--auto-approve", "--trust-all-tools",
                      "--permission-mode=bypassPermissions", "--approval-policy=never")
TRUTHY = {"true", "yes", "on", "1"}

# Check 3: tools that act, and what each would do unasked.
RISKY = {
    "send_email": ("AML.T0086", "T1048"), "post_message": ("AML.T0086", "T1048"),
    "reply_ticket": ("AML.T0086", "T1048"), "pay_invoice": ("AML.T0053", "T1657"),
    "issue_refund": ("AML.T0053", "T1657"), "update_direct_deposit": ("AML.T0053", "T1657"),
    "delete_file": ("AML.T0101", "T1485"), "write_file": ("AML.T0053", ""),
    "run_command": ("AML.T0053", "T1059.004"),
    "update_agent_settings": ("AML.T0081", "T1562.001"),
    "grant_access": ("AML.T0053", "T1098"), "reset_password": ("AML.T0053", "T1098"),
    "update_customer": ("AML.T0053", "T1565.001"), "update_account": ("AML.T0053", "T1565.001"),
}
# Check 4.
PRIVILEGED_RE = re.compile(r"admin|root|superuser|super_user|owner|master|god|full[_-]?access",
                           re.IGNORECASE)
WRITE_SCOPE_RE = re.compile(r"\*|admin|write|delete|manage|full|all", re.IGNORECASE)
# Check 5.
URL_TOOLS = ("fetch_url", "post_message", "run_command")
# Check 6: where a provider's model API lives. Extend in lure.yaml audit.provider_hosts.
PROVIDER_HOSTS = {"anthropic": ("api.anthropic.com",)}
BASE_URL_KEY_RE = re.compile(r"(baseurl|apibase|apiurl|endpoint|modelurl|apihost)$")
# Check 7: phrasing in a tool description that talks to the model, not the user.
INSTRUCTION_RE = re.compile(
    r"ignore (?:all |any )?(?:previous|prior|other|earlier) (?:instructions|rules)"
    r"|(?:always|first) (?:call|use|run) this tool"
    r"|before (?:using|calling) (?:any|other) tools?"
    r"|(?:do not|don't|never) (?:tell|inform|mention|show|notify) (?:it to )?the user"
    r"|without (?:telling|asking|informing) the user"
    r"|<\s*(?:important|system|instructions?)\s*>"
    r"|\bsecretly\b|\bsilently\b"
    r"|(?:read|include|send) [^.]*(?:\.env|~/\.ssh|id_rsa|credentials)", re.IGNORECASE)
# Check 8.
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
INTERNAL_HOST_RE = re.compile(r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:internal|local|lan|corp|"
                              r"intranet|home\.arpa)\b", re.IGNORECASE)
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
SECRECY_RE = re.compile(r"(?:never|do not|don't) (?:reveal|disclose|share|repeat) (?:this|these|"
                        r"your|the) (?:prompt|instructions|rules|system prompt)"
                        r"|keep (?:this|these|it) (?:secret|confidential)", re.IGNORECASE)
# Check 9.
WORKDIR_RE = re.compile(r"working directory is (\S+?)[.,;]?(?:\s|$)", re.IGNORECASE)
RISKY_DIRS = ("downloads", "desktop")

FIX = {
    "credentials": "Remove the credential from {where} and load it at run time from a secret "
                   "store or the environment; then rotate it, as it has been stored in plain text",
    "auto_approve": "Turn off {what} so a person confirms the agent's actions",
    "unattended": "Gate the tools that act (gated: true) before running this agent unattended, "
                  "or run it only with a person present",
    "ungated_tool": "Add a confirmation step for {tool} (gated: true), or remove the tool if "
                    "the agent does not need it",
    "privileged_credential": "Give {name} only the scopes its tools need",
    "unrestricted_egress": "Limit {what} to the domains it needs (tool domains: or "
                           "allowed_outbound_domains in lure.yaml)",
    "renders": "Set allowed_outbound_domains in lure.yaml, or set renders: false for what the "
               "chat app does not do",
    "model_endpoint": "Point {where} at the provider's own API host ({hosts}), or declare the "
                      "endpoint in audit.provider_hosts if the organization runs it",
    "mcp_unpinned": "Pin {name} to an exact version (such as @scope/server@1.4.2)",
    "mcp_http": "Use https for {name}",
    "mcp_description": "Review the description of {tool}: it addresses the model, not the user; "
                       "remove the server if it came from outside",
    "mcp_allowlist": "Approve {name} in lure.yaml mcp.approved_servers, or remove it from the "
                     "agent",
    "prompt_hygiene": "Move {what} out of the system prompt, or confirm it is meant to be there",
    "secrecy": "Do not rely on the model keeping its prompt secret; keep secrets out of it",
    "instruction_origin": "Let the agent act only on instruction files from its own repository",
    "working_dir": "Start the agent in a project folder, not {dir}",
    "external_persistence": "Keep {what} inside the organization (allowed_outbound_domains), or "
                            "confirm the outside service is approved",
}


def audit(profile: Profile, policy: Policy, key: bytes | None = None,
          use_gitleaks: bool | None = None) -> AuditResult:
    version = gitleaks_version() if use_gitleaks is not False else None
    key = key if key is not None else salt()
    result = AuditResult(profile.name, profile.sha256,
                         scanner=f"gitleaks {version}" if version else "lure patterns")
    configs = [(p, mcp.load_config(p), p.read_text(encoding="utf-8", errors="replace"))
               for p in profile.agent_config]
    servers = [s for p, _, _ in configs for s in mcp.servers(p)]
    for check in (_credentials, _auto_approve, _ungated, _privileged, _egress, _endpoint,
                  _mcp_hygiene, _mcp_allowlist, _prompt_hygiene, _instructions, _persistence):
        result.findings += check(profile=profile, policy=policy, key=key,
                                 gitleaks=bool(version), configs=configs, servers=servers)
    ignored = allow_ignored(profile, policy)
    if ignored:
        result.warnings.append(ignored)
    return result


def allow_ignored(profile: Profile, policy: Policy) -> str | None:
    """agent.allow does nothing while lure.yaml has an MCP allowlist: the
    sandbox gateway then allows the model host and approved servers only."""
    if profile.agent is None or not profile.agent.allow or policy.mcp is None:
        return None
    return (f"agent.allow ({', '.join(profile.agent.allow)}) is ignored: lure.yaml has an MCP "
            "allowlist (mcp:), so the sandbox gateway allows only the model host and the "
            "approved servers the profile uses. Approve the hosts in mcp.approved_servers, or "
            "remove agent.allow")


def _f(check: str, what: str, location: str, fix: str, severity: str | None = None,
       **extra: Any) -> Finding:
    return Finding(check, severity or CHECKS[check].severity, what, location, fix, **extra)


def _prompt_location(profile: Profile) -> str:
    return str(profile.prompt_file) if profile.prompt_file else "system_prompt"


# 1
def _credentials(profile, key, gitleaks, configs, **_) -> list[Finding]:
    sources: list[tuple[str, str]] = [(_prompt_location(profile), profile.system_prompt)]
    sources += [(f"tools[{i}].description ({t.name})", t.description)
                for i, t in enumerate(profile.tools)]
    sources += [(str(p), text) for p, _, text in configs]
    if profile.mcp_tools_snapshot is not None:
        sources.append((str(profile.mcp_tools_snapshot),
                        profile.mcp_tools_snapshot.read_text(encoding="utf-8", errors="replace")))
    if profile.agent is not None:
        # What the sandbox would pass in, beyond the model key it is meant to hold.
        sources += [(f"agent.env {n}", f"{n}={os.environ[n]}") for n in profile.agent.env
                    if n != AGENT_KEY and os.environ.get(n)]
    found = []
    for where, text in sources:
        for hit in scan(text, key, gitleaks):
            location = where if where.startswith("agent.env") else f"{where}, line {hit.line}"
            found.append(_f("credentials", f"a credential ({hit.rule})", location,
                            FIX["credentials"].format(where=where), fingerprint=hit.fingerprint))
    return found


# 2
def _norm(name: str) -> str:
    return re.sub(r"[\s_-]", "", name).lower()


def _walk(value: Any, path: str = "") -> Iterable[tuple[str, str, Any]]:
    """(dotted path, key, value) for every key in nested mappings and lists."""
    if isinstance(value, dict):
        for k, v in value.items():
            here = f"{path}.{k}" if path else str(k)
            yield here, str(k), v
            yield from _walk(v, here)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from _walk(v, f"{path}[{i}]")


def _env_pairs(text: str) -> list[tuple[int, str, str]]:
    pairs = []
    for n, line in enumerate(text.splitlines(), 1):
        m = re.match(r"^\s*(?:export\s+)?([A-Za-z_]\w*)\s*=\s*(.*?)\s*$", line)
        if m:
            pairs.append((n, m.group(1), m.group(2).strip("\"'")))
    return pairs


def _turns_on(value: Any, wanted: tuple[str, ...]) -> bool:
    if "*" in wanted:
        if isinstance(value, bool):
            return value
        if isinstance(value, (list, dict)):
            return bool(value)
        return str(value).strip().lower() in TRUTHY
    return str(value).strip().lower().replace("_", "").replace("-", "") in wanted


def _auto_approve(profile, policy, configs, **_) -> list[Finding]:
    keys = dict(AUTO_APPROVE_KEYS)
    keys.update({_norm(k): tuple(v.lower() for v in vals)
                 for k, vals in policy.audit.auto_approve_keys})
    flags = AUTO_APPROVE_FLAGS + policy.audit.auto_approve_flags
    found = []
    for path, data, text in configs:
        hits = [(where, k, v) for where, k, v in _walk(data)]
        hits += [(f"line {n}", k, v) for n, k, v in _env_pairs(text)]
        for where, k, v in hits:
            wanted = keys.get(_norm(k))
            if wanted and _turns_on(v, wanted):
                found.append(_f("auto_approve", f"{k} is set to approve without asking",
                                f"{path}: {where}", FIX["auto_approve"].format(what=k)))
        for flag in flags:
            if flag in text:
                found.append(_f("auto_approve", f"the flag {flag}", str(path),
                                FIX["auto_approve"].format(what=flag)))
    if profile.agent is not None:
        for flag in flags:
            if any(c == flag or c.startswith(flag + "=") for c in profile.agent.command):
                found.append(_f("auto_approve", f"the flag {flag}", "agent.command",
                                FIX["auto_approve"].format(what=flag)))
    if profile.schedule == "unattended" and not any(t.gated for t in profile.tools):
        found.append(_f("auto_approve", "runs unattended with no confirmation step on any tool",
                        "schedule", FIX["unattended"]))
    return found


# 3
def _ungated(profile, **_) -> list[Finding]:
    found = []
    for t in profile.tools:
        if t.maps_to in RISKY and not t.gated:
            atlas, attack = RISKY[t.maps_to]
            found.append(_f("ungated_tool", f"{t.name} ({t.maps_to}) runs with no confirmation",
                            f"tools: {t.name}", FIX["ungated_tool"].format(tool=t.name),
                            atlas=(atlas, "AML.M0029"), attack=(attack,) if attack else ()))
    return found


# 4
def _privileged(profile, **_) -> list[Finding]:
    found = []
    read_only = {t.name for t in profile.tools if t.maps_to not in RISKY}
    for c in profile.credentials:
        name, scopes, tools = c["name"], c.get("scopes", []), c.get("tools", [])
        if PRIVILEGED_RE.search(name):
            found.append(_f("privileged_credential", f"{name} is named like an admin credential",
                            f"credentials: {name}", FIX["privileged_credential"].format(name=name)))
        wide = [s for s in scopes if WRITE_SCOPE_RE.search(s) or PRIVILEGED_RE.search(s)]
        if wide and tools and set(tools) <= read_only:
            found.append(_f("privileged_credential",
                            f"{name} has {', '.join(wide)} but its tools only read",
                            f"credentials: {name}", FIX["privileged_credential"].format(name=name)))
    return found


# 5
def _egress(profile, policy, **_) -> list[Finding]:
    found = []
    allowed = policy.exposure is not None
    for t in profile.tools:
        if t.maps_to in URL_TOOLS and t.domains is None and not allowed:
            found.append(_f("unrestricted_egress", f"{t.name} can reach any host", f"tools: {t.name}",
                            FIX["unrestricted_egress"].format(what=t.name),
                            atlas=("AML.T0086",), attack=("T1048", "T1567")))
        if t.domains and any("*" in d for d in t.domains):
            found.append(_f("unrestricted_egress", f"{t.name} allows a wildcard domain",
                            f"tools: {t.name}.domains", FIX["unrestricted_egress"].format(what=t.name),
                            atlas=("AML.T0086",), attack=("T1048", "T1567")))
    if profile.agent is not None and any("*" in a for a in profile.agent.allow):
        found.append(_f("unrestricted_egress", "the sandbox allowlist has a wildcard",
                        "agent.allow", FIX["unrestricted_egress"].format(what="agent.allow")))
    if not allowed:
        on = [k for k, v in profile.renders if v is not False]
        if on:
            found.append(_f("unrestricted_egress",
                            f"the chat app fetches {' and '.join(on)} with no domain allowlist",
                            "renders", FIX["renders"], atlas=("AML.T0077",), attack=("T1567",)))
    return found


# 6
def _expected_hosts(profile, policy) -> tuple[str, tuple[str, ...]] | None:
    provider = profile.agent.provider if profile.agent is not None else profile.target
    extra = dict(policy.audit.provider_hosts).get(provider, ())
    hosts = PROVIDER_HOSTS.get(provider, ()) + tuple(h.lower() for h in extra)
    return (provider, hosts) if hosts else None


def _endpoint(profile, policy, configs, **_) -> list[Finding]:
    expected = _expected_hosts(profile, policy)
    if expected is None:
        return []
    provider, hosts = expected
    found = []

    def check(url: Any, where: str) -> None:
        host = (urlsplit(url).hostname or "").lower() if isinstance(url, str) and "://" in url \
            else None
        if host and host not in hosts:
            found.append(_f("model_endpoint", f"the {provider} model endpoint is {host}", where,
                            FIX["model_endpoint"].format(where=where, hosts=", ".join(hosts))))

    if profile.agent is not None:
        check(profile.agent.model_url, "agent.model_url")
    for path, data, text in configs:
        for where, k, v in _walk(data):
            if BASE_URL_KEY_RE.search(_norm(k)) and "mcpservers" not in _norm(where) \
                    and ".servers." not in where:
                check(v, f"{path}: {where}")
        for n, k, v in _env_pairs(text):
            if BASE_URL_KEY_RE.search(_norm(k)):
                check(v, f"{path}: line {n}")
    return found


# 7
def _mcp_hygiene(profile, servers, **_) -> list[Finding]:
    found = []
    for s in servers:
        reason = mcp.unpinned_reason(s)
        if reason:
            found.append(_f("mcp_hygiene", f"MCP server {s.name} {reason}", s.source,
                            FIX["mcp_unpinned"].format(name=s.name), severity=HIGH,
                            atlas=("AML.T0010.005", "AML.T0109"), attack=("T1195.001",)))
        if s.remote and urlsplit(s.url).scheme == "http" and \
                (urlsplit(s.url).hostname or "") not in mcp.LOCAL_HOSTS:
            found.append(_f("mcp_hygiene", f"MCP server {s.name} is reached over plain HTTP",
                            s.source, FIX["mcp_http"].format(name=s.name), severity=HIGH,
                            atlas=("AML.T0010.005",), attack=("T1557",)))
    descriptions = [(f"tools: {t.name}", t.description) for t in profile.tools]
    if profile.mcp_tools_snapshot is not None:
        descriptions += [(f"{profile.mcp_tools_snapshot}: {name}", d)
                         for name, d in mcp.snapshot_descriptions(profile.mcp_tools_snapshot)]
    for where, text in descriptions:
        if INSTRUCTION_RE.search(text):
            found.append(_f("mcp_hygiene", "a tool description gives the model instructions",
                            where, FIX["mcp_description"].format(tool=where), severity=MEDIUM,
                            atlas=("AML.T0110",), attack=()))
    return found


# 12
def _mcp_allowlist(profile, policy, servers, **_) -> list[Finding]:
    if policy.mcp is None:
        return []
    severity = CRITICAL if policy.mcp.fail_on_unlisted else HIGH
    found = []
    for name in profile.mcp_servers:
        if policy.mcp.get(name) is None:
            found.append(_f("mcp_allowlist", f"{name} is not on the approved list",
                            "mcp_servers", FIX["mcp_allowlist"].format(name=name), severity))
    for s in servers:
        problem = mcp.allowlist_problem(s, policy.mcp)
        if problem is None and s.name not in profile.mcp_servers:
            problem = f"{s.name} is in the agent's config but not in the profile's mcp_servers"
        if problem:
            found.append(_f("mcp_allowlist", problem, s.source,
                            FIX["mcp_allowlist"].format(name=s.name), severity))
    return found


# 8
def _private_ip(text: str) -> bool:
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    return ip.is_private and not ip.is_loopback


def _prompt_hygiene(profile, **_) -> list[Finding]:
    found = []
    where = _prompt_location(profile)
    for n, line in enumerate(profile.system_prompt.splitlines(), 1):
        kinds = []
        if any(_private_ip(m) for m in IPV4_RE.findall(line)):
            kinds.append("an internal IP address")
        if INTERNAL_HOST_RE.search(line):
            kinds.append("an internal host name")
        if EMAIL_RE.search(line):
            kinds.append("an email address")
        if SSN_RE.search(line):
            kinds.append("an identity number")
        for kind in kinds:
            found.append(_f("prompt_hygiene", f"the prompt holds {kind}", f"{where}, line {n}",
                            FIX["prompt_hygiene"].format(what=kind)))
        if SECRECY_RE.search(line):
            found.append(_f("prompt_hygiene", "a rule that relies on the model keeping its prompt "
                            "secret", f"{where}, line {n}", FIX["secrecy"]))
    return found


# 9
def _home_like(path: str) -> str | None:
    p = PurePosixPath(path.replace("~", "/home/user", 1) if path.startswith("~") else path)
    parts = [x.lower() for x in p.parts]
    if any(d in parts for d in RISKY_DIRS):
        return next(x for x in p.parts if x.lower() in RISKY_DIRS)
    if (len(parts) == 3 and parts[1] in ("home", "users")) or str(p) in ("/root", "/home/user"):
        return "the home folder"
    return None


def _instructions(profile, **_) -> list[Finding]:
    found = []
    for f in profile.instruction_files:
        if f["origin"] != "repo":
            found.append(_f("instruction_origin",
                            f"{f['path']} came from outside the repository ({f['origin']})",
                            "instruction_files", FIX["instruction_origin"]))
    workdir = profile.working_dir
    if workdir is None:
        m = WORKDIR_RE.search(profile.system_prompt)
        workdir = m.group(1) if m else None
    if workdir:
        risky = _home_like(workdir)
        if risky:
            found.append(_f("instruction_origin", f"the agent starts in {risky}",
                            "working_dir" if profile.working_dir else _prompt_location(profile),
                            FIX["working_dir"].format(dir=risky)))
    return found


# 10
def _persistence(profile, policy, **_) -> list[Finding]:
    found = []
    for key, value in profile.sinks:
        if value.lower() == "local":
            continue
        host = urlsplit(value).hostname if "://" in value else value.split("/")[0]
        host = (host or "").lower()
        if policy.exposure is None or not policy.exposure.allows(host):
            what = key.replace("_sink", "")
            found.append(_f("external_persistence", f"the agent's {what} is kept at {host}", key,
                            FIX["external_persistence"].format(what=what), severity=INFO))
    return found

