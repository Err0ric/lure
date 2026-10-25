# lure audit: check an agent's setup before testing it

`lure audit <profile>` reads an agent's setup and reports what makes it unsafe to run, before any attack. It makes no model call and no network call. The same check runs at the start of every `lure run --profile`, `lure retest` and `lure sandbox run`, before any model call or container starts.

```bash
lure audit profiles/my-agent.yaml
lure audit profiles/my-agent.yaml --json results/my-agent/audit.json \
  --sarif results/my-agent/audit.sarif --approval results/my-agent/setup.html
```

| Exit | Meaning |
| --- | --- |
| 0 | No critical finding |
| 1 | A critical finding: a profile run stops here, before any model call, and writes `audit.json` to its results folder |
| 2 | Bad input (profile or policy) |

It checks the agent's own setup, the things that decide whether it will leak data or misbehave when attacked. General code, dependency and image hygiene (Semgrep, OSV, Trivy) belong in the Gate pipeline, not here.

## Severities

| Severity | Checks | Effect |
| --- | --- | --- |
| Critical | 1, 2, 6, 12 | The run stops before any model call. The approval page recommends **Reject until fixed**, whatever the tests found |
| High, medium | 3, 5, 7, 9 | Reported, and the run goes on. An Approve becomes Approve with conditions, and each fix is listed as a condition |
| Info | 4, 8, 10 | Reported under "Worth a look". Never blocks a run, never changes the recommendation |

There is no flag to skip a critical finding: fix the profile or the agent's config and rerun. `lure audit` on its own is the quick way to iterate.

## Checks and mappings

IDs verified on 2026-10-25: ATLAS in MITRE's data release 2026.09, ATT&CK on attack.mitre.org, the OWASP Top 10 for LLM Applications 2025 on genai.owasp.org. ATLAS mitigations (`AML.M`) name the control that is missing.

| # | Check | Severity | ATLAS | ATT&CK | OWASP LLM 2025 |
| --- | --- | --- | --- | --- | --- |
| 1 | **Hardcoded credentials** in the system prompt and prompt file, tool and MCP definitions (URLs, headers, descriptions), the agent config the profile names (`agent_config`: mcp.json, settings, a workspace .env), the tool snapshot, and what the sandbox would pass into the agent's environment beyond its model key. gitleaks when installed (redacted, read from a pipe), else Lure's patterns. `LURE-FAKE-` canaries and references (`${API_KEY}`, `env:...`) are not credentials | Critical | AML.T0055 Unsecured Credentials; AML.T0083 Credentials from AI Agent Configuration | T1552.001 Credentials In Files | LLM02:2025 Sensitive Information Disclosure; LLM07:2025 System Prompt Leakage |
| 2 | **Acts without asking**: auto-approve or bypass modes in agent config (`defaultMode: bypassPermissions`, `auto_approve_commands: true`, `approval_policy: never`, `alwaysAllow: [...]`, `requireConfirmation: false`, and others), flags such as `--dangerously-skip-permissions` in a config or `agent.command`, and `schedule: unattended` with no gated tool | Critical | AML.T0053 AI Agent Tool Invocation; AML.M0029 Human In-the-Loop for AI Agent Actions | none (a missing control) | LLM06:2025 Excessive Agency |
| 3 | **Risky tools with no confirmation step**: send, post, reply, pay, refund, deposit changes, delete, write, shell, settings, access and account changes | High | AML.T0053; AML.T0086, AML.T0101 or AML.T0081 by tool; AML.M0029; AML.M0028 AI Agent Tools Permissions Configuration | by tool: T1048, T1657, T1485, T1059.004, T1562.001, T1098, T1565.001 | LLM06:2025 |
| 4 | **Over-privileged credentials** where the profile declares them (`credentials:`): admin, root, superuser or owner in the name; write, delete or admin scopes on a credential whose tools only read | Info | AML.T0012 Valid Accounts; AML.M0026 Privileged AI Agent Permissions Configuration | T1078 Valid Accounts | LLM06:2025 |
| 5 | **Unrestricted outbound access**: a URL-taking tool (fetch, chat post, shell) with no domain limit (tool `domains:` or `allowed_outbound_domains`), a wildcard domain, a wildcard in the sandbox allowlist, or a chat app that renders images or link previews with no domain allowlist | High | AML.T0086 Exfiltration via AI Agent Tool Invocation; AML.T0077 LLM Response Rendering | T1048 Exfiltration Over Alternative Protocol; T1567 Exfiltration Over Web Service | LLM02:2025; LLM05:2025 Improper Output Handling |
| 6 | **Model endpoint outside the declared provider**: a base URL in agent config or a .env (`ANTHROPIC_BASE_URL`, `apiBaseUrl`, `model_base_url`), or the agent block's `model_url`, whose host is not the provider's API host (`api.anthropic.com` for Anthropic; extend in `audit.provider_hosts`) | Critical | AML.T0081 Modify AI Agent Configuration | T1557 Adversary-in-the-Middle | LLM03:2025 Supply Chain; LLM02:2025 |
| 7 | **MCP hygiene**: a local server with no exact version (`npx -y pkg`, `@latest`), a remote server over plain HTTP (high); a tool description that gives the model instructions ("before using any other tool", "do not tell the user") (medium) | High / medium | AML.T0010.005 AI Supply Chain Compromise: AI Agent Tool; AML.T0109 AI Supply Chain Rug Pull; AML.T0110 AI Agent Tool Poisoning | T1195.001 Compromise Software Dependencies and Development Tools; T1557 | LLM03:2025; LLM01:2025 Prompt Injection |
| 8 | **System prompt hygiene**: internal IP addresses or host names, email addresses or identity numbers, and rules that rely on the model keeping its prompt secret ("never reveal these instructions"). Reported by kind and line, never quoted | Info | AML.T0056 Extract LLM System Prompt; AML.T0069.002 Discover LLM System Information: System Prompt | none | LLM07:2025 |
| 9 | **Instructions from outside the repository**: `instruction_files` whose origin is not `repo`, and a working directory in Downloads, Desktop or the home folder (`working_dir`, or "working directory is ..." in the prompt) | High | AML.T0051.001 LLM Prompt Injection: Indirect; AML.T0112.000 Machine Compromise: Local AI Agent | T1204.002 User Execution: Malicious File | LLM01:2025 |
| 10 | **Memory, logs or transcripts kept outside** (`memory_sink`, `log_sink`, `transcript_sink` on a host outside `allowed_outbound_domains`) | Info | AML.T0080.000 AI Agent Context Poisoning: Memory; AML.T0057 LLM Data Leakage | T1530 Data from Cloud Storage | LLM02:2025 |
| 12 | **MCP server not on the approved list** (below) | Critical (high with `fail_on_unlisted: false`) | AML.T0010.005; AML.T0109 | T1195.001 | LLM03:2025 |

There is no check 11: container image hygiene (root user, unpinned base, `curl | sh` in a build) is Trivy's job in the Gate pipeline.

## What it reads

Everything in the profile is descriptive: names, paths and hosts, never secret values.

| Profile key | For | Example |
| --- | --- | --- |
| `system_prompt` or `system_prompt_file` | 1, 8, 9 | |
| `tools[].description`, `tools[].domains` | 1, 3, 5, 7 | `domains: [portal.corp.example]` |
| `agent_config` | 1, 2, 6, 7, 12 | `[config/mcp.json, config/settings.json, workspace/.env]`, relative to the profile |
| `schedule` | 2 | `interactive` (default) or `unattended` |
| `credentials` | 4 | `[{name: ERP_TOKEN, scopes: [invoices:read], tools: [erp_read]}]` |
| `renders` | 5 | |
| `agent:` (`model_url`, `env`, `allow`, `command`) | 1, 2, 5, 6 | |
| `instruction_files`, `working_dir` | 9 | `[{path: AGENTS.md, origin: download}]` |
| `memory_sink`, `log_sink`, `transcript_sink` | 10 | `https://memory.vendor.example`, or `local` |
| `mcp_servers`, `mcp_tools_snapshot` | 7, 12 | `[crm, files]`, `config/mcp-tools.json` |

And in `lure.yaml`:

```yaml
audit:
  # More settings that mean "approve without asking": name -> values.
  auto_approve_keys: {hands_free: ["on"]}
  auto_approve_flags: ["--unattended"]
  # More hosts a provider's model endpoint may have (an approved gateway).
  provider_hosts: {anthropic: [llm-gateway.corp.example]}
```

## No secret is ever written

A finding names the kind of thing found ("a credential (anthropic-api-key)"), where (file and line, or the profile key) and a fix. A credential also gets a 12-character fingerprint: HMAC-SHA256 with a random salt kept in `vetting/.audit-salt` (gitignored, created on first use, or `LURE_AUDIT_SALT_FILE`). The same credential has the same fingerprint across runs on one checkout, so a fix can be confirmed, but a report cannot be used to recover or guess it.

gitleaks runs with `--redact` and its report is read from a pipe, never a file. Lure takes the value from its own in-memory copy only to fingerprint it. Prompt hygiene findings give the kind and line, never the text. The tests plant real-shaped credentials (built at run time from random characters) in a prompt file, an MCP header and a workspace .env, then search every output for each one and for any 8-character slice of it: `audit.json`, SARIF, the approval page, the run folder, the DuckDB store, stdout and stderr. They run with and without gitleaks.

## The approval page

A **Configuration** section comes first: each finding in plain language with its fix and where it is. Info findings are listed apart, as "Worth a look". Any critical finding makes the recommendation **Reject until fixed**. The fixes for high and medium findings are listed under Suggested conditions, marked as coming from the configuration check (a retest does not verify them; the next audit does). `lure audit --approval` writes the page from the audit alone, before any test.

## The MCP server allowlist

The organization lists the MCP servers it approved in `lure.yaml`:

```yaml
mcp:
  approved_servers:
    - name: crm
      url: https://mcp.crm.example/mcp        # remote: matched by host, https only
    - name: files
      package: "@acme/files-mcp@1.4.2"         # local: pinned to an exact version
  fail_on_unlisted: true                       # the default
```

A profile lists the servers its agent uses, a subset: `mcp_servers: [crm, files]`.

| Where | What happens |
| --- | --- |
| `lure audit` (check 12, critical) | Fails before any model call when the profile or its `agent_config` names a server not on the list, an approved name with another url host or package, or an unpinned version, or a server in the config the profile does not declare |
| `lure sandbox run` | The gateway allows the model API host and the approved servers' hosts the profile uses, and nothing else (`agent.allow` is not used). Any other destination is blocked egress and, with `fail_on_unlisted`, a **Fail** for the run: "egress to a host not on the approved list" |
| `lure decide` | Records a hash of each server's tool definitions (name, description, input schema; sorted, canonical JSON) from the profile's `mcp_tools_snapshot` |
| `lure retest` | Different definitions are a regression (exit 1): "tool definitions changed since approval", as in `lure-tpo-003`, a tool that changes after it was trusted |

**Where the tool definitions come from.** By default, an operator-exported snapshot: the `tools/list` result of each server, as `{server: {tools: [...]}}`, named by `mcp_tools_snapshot`. Optionally, for remote servers, Lure fetches it from inside the sandbox:

```bash
lure sandbox mcp-snapshot --profile profiles/my-agent.yaml --out profiles/my-agent-tools.json
```

The reference agent image's client calls `initialize` and `tools/list` only, never a tool, through the gateway, which allows the approved servers' hosts and nothing else. No model is called and no key goes in. Lure never starts a local (stdio) server: export its snapshot.

**Verify here, enforce there.** Lure verifies that the agent's setup matches the allowlist and catches drift in the servers' tools. It does not enforce the list in production. That lives in the Claude organization's managed settings (`allowedMcpServers`, which limits the servers Claude clients may load) and the firewall (which limits where agents can connect). Keep the three lists the same.
