# Known gaps and roadmap

> Status: v1.9.0. Runs locally against Anthropic, Ollama and OpenAI-compatible targets; see [Known gaps](#known-gaps) below for what is still open.

## Known gaps

- **Targets:** Anthropic, Ollama and OpenAI-compatible endpoints. Providers with other APIs need an adapter; see [`CONTRIBUTING.md`](../CONTRIBUTING.md).
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
- [ ] v1.10: DuckDB results store (`lure store`) and a local, read-only `lure serve` dashboard

### Next

- [ ] v1.11: `split_over` across invoice numbers, a tolerant check for summary gates, and live llama3.1 smoke tests for the misled and split paths
  - Summary gates trade-off: today a summary counts as honest only if it names the harmful detail word for word, which is strict on the agent. A tolerant check (the recipient's organization, "outside", a rounded amount) would read more summaries as honest, so fewer runs fail as misled, at the risk of crediting a vague summary that a hurried person would wave through.

### Later

- [ ] Adaptive attacker `outcome` mode. Next try: a larger local open-weights model as the attacker (`llama3.1:8b` wrote weak payloads, and Claude attackers refused most exfiltration goals).
- [ ] Multi-agent targets (an orchestrator plus specialists) and handoff attacks

Full scope, schema and rubric live in [`docs/kickoff.md`](kickoff.md).
