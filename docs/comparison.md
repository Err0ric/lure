# Lure compared with garak, promptfoo, PyRIT and AgentDojo

These tools overlap, and several are larger and more mature than Lure. This page states what each one does, from its own repository and docs, so you can pick the right one or use several together.

Checked on 2026-10-26 against each project's default branch and official docs (sources at the end). Projects move fast: check the sources before relying on a row.

## At a glance

| | Lure | garak | promptfoo | PyRIT | AgentDojo |
| --- | --- | --- | --- | --- | --- |
| **What it is** | Harness that attacks a tool-using agent and decides whether to approve it | LLM vulnerability scanner | CLI and library for evaluating and red teaming LLM apps and agents | Framework for red teaming generative AI systems | Benchmark environment for prompt injection attacks and defenses on agents |
| **Scope** | Runtime agent behavior: indirect and direct prompt injection, jailbreak, data leakage, tool abuse, tool poisoning, memory poisoning, self-modification | Model and dialog failures: prompt injection, jailbreaks, data leakage, hallucination, toxicity, encoding attacks and more | Evals plus red teaming: dozens of plugins covering injection, jailbreaks, harmful content, agent and API risks | Building blocks for single- and multi-turn attacks: targets, converters, scorers, memory, scenarios | 4 task suites (workspace, Slack, travel, banking); the paper's version has 97 tasks and 629 security test cases |
| **Agent and tool testing** | Core: every attack gives the agent tools and judges the tool-call log | `agent_breaker` probe: a red-team model attacks a tool-using agent through conversation | Yes: MCP, tool discovery, excessive agency, BOLA, BFLA, memory poisoning, indirect injection and coding-agent plugins | Targets can call tools, including MCP servers; an XPIA workflow for cross-domain (indirect) injection | Core: agents call simulated tools over untrusted data; utility and security are both scored |
| **How tools run** | Mock tools that log and return fake data; a real agent runs in Lure's container | No tools of its own; it talks to the model or endpoint | Your agent's real tools, through its provider | Your target's real tools | Simulated Python tools over in-memory state |
| **Sandboxing** | `lure sandbox run`: throwaway container (or VM) behind an egress gateway that blocks and logs other hosts | Not part of the tool | Relies on the agent's own sandbox settings and your harness; the coding-agent guide documents isolation patterns | Experimental Docker sandbox for its program-execution scorer, not for the target | Not needed: tools are simulated |
| **Framework mapping** | MITRE ATLAS and ATT&CK technique IDs on every attack and result; Arcanum taxonomy codes; OWASP LLM Top 10 IDs on `lure audit` findings | Probes tagged with OWASP LLM Top 10 and AVID categories | Presets for OWASP LLM, OWASP Agentic, OWASP API, NIST AI RMF, MITRE ATLAS (tactic level), EU AI Act, ISO 42001 | Not built in | None |
| **Reports** | Static HTML, Markdown, SARIF; one-page approval report, `lure decide`, CI gate exit codes | JSONL log, HTML digest, AVID report | Web report view with vulnerabilities and remediations; CI integration | HTML scenario report, JSON outputs, a results database | Benchmark scores (utility, attack success) and a public results page |
| **Approval workflow** | Yes: profile of your agent, approval report, decide, retest | No | No dedicated approve/reject step | No | No |
| **License** | Apache-2.0 | Apache-2.0 | MIT (paid cloud and enterprise offerings also exist) | MIT | MIT |

## Where each one is stronger than Lure

| Tool | Stronger at |
| --- | --- |
| **garak** | Breadth against the model itself: 45 probe modules, many jailbreak and encoding families, and detectors. Better for scanning a raw model or chat endpoint, where Lure does not apply. |
| **promptfoo** | Breadth and integration: far more plugins, generated test cases, evals beyond security, broader compliance presets, and tests against your agent's real tools. A larger community and commercial support. |
| **PyRIT** | Flexibility for red teamers: composable attacks, converters and scorers, multi-turn orchestration, and many targets. Better for building custom attack campaigns. |
| **AgentDojo** | Research-grade measurement: a published benchmark with fixed tasks, utility measured alongside security, and built-in defenses (tool filter, PI detector, spotlighting, prompt repetition) for comparing defenses across models. |

## Where Lure is different

- **Verdicts from the tool-call log.** A Fail means the agent called a tool with attacker-chosen arguments, not that a judge thought the reply looked bad.
- **Safe by construction.** Mock tools only, fake data under `.example`, and model APIs as the only network calls; a real agent runs only in a container behind the egress gateway.
- **An approval decision.** A profile of your agent, a one-page approval report, `lure decide` and `lure retest` answer "should this agent be approved?", not only "what broke?".
- **Every result mapped.** Each attack and finding carries MITRE ATLAS and ATT&CK IDs, checked on atlas.mitre.org and attack.mitre.org.

These tools combine well: scan the model with garak, build custom campaigns with PyRIT or promptfoo, compare defenses on AgentDojo, and gate a specific agent's approval with Lure.

## Sources

| Tool | Repository | Docs |
| --- | --- | --- |
| garak | [NVIDIA/garak](https://github.com/NVIDIA/garak) | [docs.garak.ai](https://docs.garak.ai), [reference.garak.ai](https://reference.garak.ai) |
| promptfoo | [promptfoo/promptfoo](https://github.com/promptfoo/promptfoo) | [Red teaming](https://www.promptfoo.dev/docs/red-team/), [MITRE ATLAS](https://www.promptfoo.dev/docs/red-team/mitre-atlas/), [MCP plugin](https://www.promptfoo.dev/docs/red-team/plugins/mcp/), [Coding agents](https://www.promptfoo.dev/docs/red-team/coding-agents/) |
| PyRIT | [microsoft/PyRIT](https://github.com/microsoft/PyRIT) (moved from Azure/PyRIT, now archived) | [microsoft.github.io/PyRIT](https://microsoft.github.io/PyRIT/) |
| AgentDojo | [ethz-spylab/agentdojo](https://github.com/ethz-spylab/agentdojo) | [agentdojo.spylab.ai](https://agentdojo.spylab.ai), [paper](https://arxiv.org/abs/2406.13352) |
