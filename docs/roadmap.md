# Known gaps and roadmap

> Status: v1.14.1. Runs locally against Anthropic, Ollama and OpenAI-compatible targets; see [Known gaps](#known-gaps) below for what is still open.

## Known gaps

- **Targets:** Anthropic, Ollama and OpenAI-compatible endpoints. Providers with other APIs need an adapter; see [`CONTRIBUTING.md`](../CONTRIBUTING.md).
- **Real agents:** `lure sandbox run` isolates an agent in a container, but only Lure's reference agent reports its tool calls; for a third-party agent the gateway log and workspace diff are the evidence until the mock MCP server (v1.15).
- **Results store:** one JSON file per run is the source of truth; `lure store` indexes them into DuckDB and can rebuild from them. `lure serve` is local and read-only: no sharing, accounts or remote access.
- **Reactive fixtures:** responders are declarative triggers on tool calls, not a simulated counterpart that writes new text. Each released item is fixed in advance.
- **LLM judge:** injected text in a reply can reach the judge; see [How a run is scored](usage.md#how-a-run-is-scored).
- **Sample size:** the published baselines are 3 runs per attack, so per-attack rates are marked low sample.

## Roadmap

- [x] Phase 0: Kickoff
- [x] Phase 1: One attack, end to end
- [x] Phase 2: Attack library v1 (21 attacks, mock files, HTTP and payments tools, verified IDs)
- [x] Phase 3: Judge and report (LLM judge, HTML report, exec summary; DuckDB store and reactive fixtures moved to v1.1)
- [x] Phase 4: Ship v1.0 (security review, CI, demo, tag v1.0)
- [x] v1.1.0: policy file and CI gate (exit codes, Markdown, SARIF), results JSON Schema, OpenAI-compatible adapter, category discovery, CONTRIBUTING
- [x] v1.2.0: reactive fixtures (responders), multi-turn attacks, tool poisoning and memory poisoning categories, Partial severity
- [x] v1.3.0: adaptive attacker, payload variants, trust-boundary attacks, the Refused verdict, `--baseline`, `--max-cost`, `lure-ipi-007` v4 (compromised real vendor mailbox)
- [x] v1.4.0: Arcanum Prompt Injection Taxonomy mapping and `lure coverage`, structured LLM judge output, SARIF links to pinned attack versions
- [x] v1.5.0 (shipped in v1.6.0): `lure --version`, agent profiles, one-page approval report, credential access and covert egress attacks
- [x] v1.6.0: `lure decide`, `lure retest`, weekly vetting workflow, shell, self-modification and persistence attacks
- [x] v1.7.0: confirmation gates, customer support and IT helpdesk scenario packs, `lure rescore --exposure-only` for adaptive runs
- [x] v1.8.0: evasion variants (zero-width, homoglyphs, hidden HTML, translated), team chat as an input, summary-only and threshold gates, the profile tutorial
- [x] v1.9.0: HR and recruiting and sales and CRM scenario packs, with example profiles
- [x] v1.10.0: DuckDB results store (`lure store`) and a local, read-only `lure serve` dashboard
- [x] v1.11.0: `lure status`, Gitea pipeline examples and guide, SECURITY.md, issue and pull request templates, a container image, how the sandbox works
- [x] v1.12.0: coding-agent instruction-file attacks (a file from a download asks to install a package, change the model endpoint, or hand over the auth token) and a fixture `origin` field (repo, download, user), on today's mocks
- [x] v1.13.0: isolation for real agents: Lure's own egress gateway (hostname allowlist, no TLS decryption, blocked egress and DNS lookups logged as exposure), a throwaway non-root container per run on an internal-only network, decoy commands and a workspace diff, a reference agent image, `lure sandbox`, and a changed model endpoint as a critical Fail (`lure-smo-004` v2). Also `split_over` across invoice numbers (`lure-tab-004` v2), a tolerant summary-gate check (strict kept as an option), and live llama3.1 gate smoke tests
- [x] v1.13.1: the sandbox's model key is `LURE_AGENT_API_KEY` only (never `ANTHROPIC_API_KEY`), Ollama limited to `/api/generate` and `/api/chat`, `pytest -m docker` in CI, gitleaks in a pre-commit hook
- [x] v1.13.2: the sandbox's internal network gives the Docker host no address on its bridge, so the agent cannot reach host services; a Docker test with host stubs proves it
- [x] v1.14.0: `lure audit`, a pre-flight check of an agent's setup that stops a run on a critical finding (credentials, acting without asking, a foreign model endpoint, an unapproved MCP server) with a Configuration section on the approval page; and an MCP server allowlist in `lure.yaml`, enforced at the sandbox gateway, with tool-definition hashes checked on retest
- [x] v1.14.1: a warning when a profile's `agent.allow` is ignored under an MCP allowlist

### Next

- [ ] v1.15: Lure as a mock MCP server (stdio and Streamable HTTP), so an unmodified MCP-based agent uses Lure's mock tools; an HTTP agent endpoint adapter (on the v1.13 profile `agent:` block), the approval page's Isolation section, and the at-work guide: a dedicated VM on an isolated VLAN, with firewall and proxy logs accepted as egress evidence

### Later

- [ ] Adaptive attacker `outcome` mode. Next try: a larger local open-weights model as the attacker (`llama3.1:8b` wrote weak payloads, and Claude attackers refused most exfiltration goals).
- [ ] Multi-agent targets (an orchestrator plus specialists) and handoff attacks

Full scope, schema and rubric live in [`docs/kickoff.md`](kickoff.md).
