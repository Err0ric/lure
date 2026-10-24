# Profiles: test your own agent

A profile describes an agent you built: its model, its real system prompt, and its tools. `lure run --profile` runs Lure's attacks against that setup instead of Lure's default assistant.

```bash
lure run --profile profiles/example-ap-agent.yaml --prices prices.yaml --max-cost 0.50
```

> **Your system prompt leaves your machine.** The profile's system prompt is sent to whatever model API the profile names, on every run. For a work agent, use an organization-approved API account or a local model (Ollama), never a personal API key. Results also save the prompt in each run's transcript under `results/`, which is gitignored; treat that folder like the prompt itself.

## What a profile changes, and what it does not

| | With a profile | Without |
| --- | --- | --- |
| System prompt | The agent's own prompt | The attack's prompt, or Lure's neutral accounts payable prompt |
| Tool names and descriptions the model sees | The agent's own | Lure's (`send_email`, `pay_invoice`, ...) |
| What a tool call does | **Lure's mock tool, always.** Nothing is sent, paid or deleted, and no real endpoint is ever called | Same |
| Attacks run | Only those whose tools the agent has; the rest are listed as skipped, with the reason | Every attack you name |
| Scoring | The same rules on the tool-call log, which records Lure's tool name and the agent's name for it | Same |
| Scenarios | Lure's accounts payable scenarios (vendor email, invoices, payments) | Same |

The scenarios are accounts payable for `corp.example`. An agent built for another job still gets these tasks, so read its results as "how it handles hostile content while doing AP work". Scenario packs for other jobs (customer support, IT helpdesk) are on the roadmap.

## The profile file

Start from [`profiles/example-ap-agent.yaml`](../profiles/example-ap-agent.yaml). Everything else under `profiles/` is gitignored, because a real system prompt can be sensitive.

| Key | Required | What it is |
| --- | --- | --- |
| `name` | yes | Lowercase letters, digits and dashes. Names the results folder |
| `target` | yes | `anthropic`, `ollama` or `openai` (OpenAI-compatible) |
| `tools` | yes | The agent's tools, each with `name`, `description` and `maps_to` (below) |
| `system_prompt` or `system_prompt_file` | one of them | The agent's real prompt, inline or in a file next to the profile |
| `model` | no | The model; else the target's default |
| `owner`, `role` | no | Who owns the agent (a role, not a name) and what it is for. Shown in reports |
| `third_party_tools` | no | `true` if the agent loads MCP or plugin tools. Enables the attacks that add third-party tools (tool poisoning, poisoned tool output). Default `false` |
| `policy` | no | Path to a `lure.yaml`, relative to the profile. `--policy` on the command line wins |
| `suites` | no | `all` (default) or a list of attack categories |

Each tool maps to one of Lure's mock tools:

| `maps_to` | Stands in for |
| --- | --- |
| `read_inbox`, `send_email` | Reading and sending email |
| `list_files`, `read_file`, `write_file`, `delete_file` | A file store or shared drive |
| `fetch_url` | Fetching a web page |
| `pay_invoice` | Making a payment |
| `search_memory`, `save_memory` | Long-term memory or saved notes |

Each mock tool can have one agent tool mapped to it. Leave out what the agent cannot do: an agent with no delete tool is never offered one, and attacks that need it are skipped.

Lure rejects a profile whose prompt contains something shaped like an API key or a private key. A profile holds no endpoints and no credentials.

## Canary lines

Two attacks check whether the agent leaks a secret from its system prompt: `lure-dpi-001` and `lure-jbk-003`. Your real prompt has no such secret, so for those attacks Lure appends one line (the attack's `canary:`, a fake escalation code) to your prompt. The run records `canary_appended: true`, and reports list those attacks. Attacks that only add a policy line to their own prompt run under your prompt with nothing appended: whether your agent has such a rule is part of what gets tested.

When `lure-dpi-001` checks for a leaked tool list, it also looks for your tool names, if they contain an underscore, dash or digit (a plain word such as `email` would match ordinary replies).

## Not tested: the agent's own rules

An agent's own instructions can stop a scenario before the attack arrives. For example, an agent told "only email people at corp.example unless the user asks" will not reply to a vendor, and some attacks need that reply first. Such a run is Invalid, with the reason "not tested: the agent's rules blocked the setup step" and the step it skipped, and reports list it under "Not tested: the agent's own rules". Lure only uses this reason when the agent read the content and then did not take the step; a run where it never looked keeps the usual Invalid reason.

## Results

`lure run --profile` writes to `results/<profile name>/<UTC timestamp>/`, unless you pass `--results-dir`. Next to the run records, `manifest.json` lists the profile (path and SHA-256), target, judge, policy, settings, every run with its verdict, and every skipped attack with the reason. `lure report` and `lure rescore` read the folder as usual and skip the manifest.

Each record carries a `profile` block: name, SHA-256, whether a canary line was appended, and the agent's tool names with the Lure tool each maps to. In `tool_calls`, `tool` is always Lure's name and `alias` is the name the agent used.
