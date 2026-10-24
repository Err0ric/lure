# config_audit (future stage, not implemented)

Status: design stub only. No code, no CLI command, no roadmap date. This page
records the intended scope so contributors do not build it into the wrong
place.

## Why

`lure run` tests what an agent *does* when attacked. Much of the damage an
injected agent can do is decided earlier, by its configuration: which tools
it has, which run without approval, and which MCP servers it can reach. A
static check of that configuration would catch a dangerous setup before any
run, and explain run results ("it sent the email because `send_email` was
auto-approved").

## Scope

Read an agent's settings files and flag settings that widen what an
injected agent could do.

| Check | Example finding |
| --- | --- |
| Tools that act without approval | `send_email`, `delete_file` or a payment tool is auto-approved |
| Broad tool grants | Wildcard tool or shell permissions instead of a named list |
| MCP servers | A server reachable over the network rather than local stdio; a server whose tools overlap the agent's high-risk actions |
| MCP server scope | Filesystem or HTTP servers rooted at `/` or with no host allow-list |
| Outbound reach | No egress or recipient allow-list for tools that send data out |
| Untrusted content plus action | The same agent both reads outside content (email, web) and holds send, delete or pay tools with no approval step |

## Non-goals

- Secrets scanning, dependency scanning or general app security. Other tools
  do that well; Lure stays agent-only.
- Judging a config as safe. A clean audit means no listed check fired, not
  that the agent resists injection; `lure run` is still the test.
- Any vendor- or org-specific config format in core. Formats come in through
  readers, the way models come in through adapters.

## How it would fit

| Piece | Plan |
| --- | --- |
| Command | `lure audit <config file or folder>`, separate from `lure run` |
| Readers | One per settings format, behind a small interface (like `lure/adapters/base.py`) |
| Checks | One module per check, each with an id (e.g. `lure-cfg-001`), severity, ATLAS and ATT&CK IDs |
| Policy | Same `lure.yaml`: `categories` and `overrides` apply to check ids; `fail_on` severity applies as for attacks |
| Exit codes | Same as `lure run`: 0 pass, 1 policy fail, 2 error |
| SARIF | Here a finding *is* in a file, so locations point at the config file and line of the setting |
| Safety | Read-only. Never starts an MCP server, never calls a tool, never follows a URL in the config |

## Open questions

- Which settings formats to support first, and how to keep readers generic.
- ATLAS mapping for configuration findings. Candidates such as AML.T0053
  (AI Agent Tool Invocation) describe the abuse, not the misconfiguration;
  verify current agent techniques on https://atlas.mitre.org/ before
  assigning IDs.
- Whether `lure report` should join audit findings with run results for the
  same agent.
