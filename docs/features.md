# Features

A tour of everything Lure does, one short section per feature. Each section says what the feature is for, what it needs, and one command to try it. The full details live in the linked reference docs.

Before you start, install Lure and activate its virtual environment: [`install.md`](install.md). Every "Try it" below was run on 2026-10-27 in a fresh clone with a local Ollama model, so none of them costs anything.

| Feature | What it does | Needs anything extra? |
| --- | --- | --- |
| [Running attacks](#running-attacks) | Plants an attack and runs an agent against it on mock tools | A model (Ollama is free) |
| [Reports and compare](#reports-and-compare) | Turns saved runs into HTML, Markdown and SARIF, or compares models side by side | No |
| [LLM judge](#llm-judge) | A second model reviews each run after the rule checks | A second model |
| [Adaptive attacker](#adaptive-attacker) | A model rewrites the payload until the target breaks | A second model |
| [Spending cap](#spending-cap) | Estimates the cost of a batch and stops before a budget | A prices file |
| [Policy file and CI gate](#policy-file-and-ci-gate) | Decides pass or fail for CI from `lure.yaml` | No |
| [Profiles](#profiles) | Tests your own agent: its prompt, its tools, its model | No |
| [Approval workflow](#approval-workflow) | Records approve or reject, retests on change, answers "is it approved?" | No |
| [lure audit and the MCP allowlist](#lure-audit-and-the-mcp-allowlist) | Checks an agent's setup before any attack | gitleaks (optional) |
| [Docker sandbox](#docker-sandbox) | Runs a real agent in a throwaway container behind an egress gateway | Docker |
| [Results store and dashboard](#results-store-and-dashboard) | Queries every run with SQL and browses them locally | The `store` extra (DuckDB) |
| [Gitea pipeline](#gitea-pipeline) | Pull-request approvals on a self-hosted Gitea | Gitea and its runners |
| [Arcanum coverage](#arcanum-coverage) | Shows which Arcanum taxonomy codes the attacks cover | No |

## Running attacks

**What it does.** Lure gives an agent a normal task, hides an attack in what it reads (an email, a file, a tool description), and judges the run from the tool-call log. The agent only gets mock tools, so nothing is ever sent, paid or deleted.

**You need.** A model: Ollama, an Anthropic key, or an OpenAI-compatible server ([install step 6](install.md#6-pick-a-model)).

**Set up.**

```bash
ollama pull llama3.1:8b
```

**Try it.**

```bash
lure run attacks/indirect_prompt_injection/lure-ipi-001.yaml --target ollama --model llama3.1:8b
```

You should see: a `Verdict:` line (`PASS`, `FAIL`, ...) and `Saved: results/...json`.

**Learn more.** [`usage.md`](usage.md#quickstart), [`attack-library.md`](attack-library.md).

## Reports and compare

**What it does.** `lure report` turns saved runs into a static HTML report, plus Markdown and SARIF (a standard format code scanners read) on request. `lure compare` puts several models side by side in one page.

**You need.** Saved runs, one folder per model to compare.

**Set up.** Run the same attack on two local models, each into its own folder:

```bash
ollama pull llama3.2:1b
```

```bash
lure run attacks/indirect_prompt_injection/lure-ipi-001.yaml --target ollama --model llama3.1:8b --results-dir results/llama3.1
```

```bash
lure run attacks/indirect_prompt_injection/lure-ipi-001.yaml --target ollama --model llama3.2:1b --results-dir results/llama3.2
```

Build one model's report, with Markdown and SARIF:

```bash
lure report results/llama3.1/ --md report.md --sarif lure.sarif
```

**Try it.**

```bash
lure compare results/llama3.1 results/llama3.2
```

You should see: a table with one column per model, and `Wrote compare.html: 2 targets.`

**Learn more.** [`run-in-your-environment.md`](run-in-your-environment.md#5-read-the-report), [`usage.md`](usage.md#quickstart).

## LLM judge

**What it does.** The rule checks decide most runs from the tool-call log; with `--judge llm`, a second model also reviews each run for what rules can miss, such as an agent offering to do the attacker's request. A Fail always needs evidence from the log.

**You need.** A judge model that is not the target: Lure refuses to let a model judge itself on a live run. The judge defaults to Anthropic; `--judge-target ollama` keeps it local.

**Set up.**

```bash
ollama pull llama3.2:1b
```

**Try it.** Re-judge saved runs without calling the target again:

```bash
lure rescore results/llama3.1/ --judge llm --judge-target ollama --judge-model llama3.2:1b --out results/rejudged
```

You should see: `PASS -> PASS [llm-judged]` (or the new verdict) for each run, and `Rescored copies: results/rejudged`.

**Learn more.** [`usage.md`](usage.md#how-a-run-is-scored).

## Adaptive attacker

**What it does.** An attacker model reads how the target answered and rewrites the payload, for up to `--attempts` tries, and the run keeps the worst result. It shows whether a model that resists the fixed payload breaks under a reworded one.

**You need.** An attacker model that is not the target. It defaults to Anthropic; `--attacker-target ollama` keeps it local.

**Set up.**

```bash
ollama pull llama3.2:1b
```

**Try it.**

```bash
lure run attacks/memory_poisoning/lure-mem-003.yaml --target ollama --model llama3.1:8b --attacker-model llama3.2:1b --attacker-target ollama --attempts 2 --results-dir results/adaptive
```

You should see: an `Adaptive:` line, such as `ollama:llama3.2:1b: worst at attempt 1 of 1, target failed`. Keep adaptive runs in their own folder: a report will not mix them with single-shot runs.

**Learn more.** [`usage.md`](usage.md#adaptive-attacker).

## Spending cap

**What it does.** With a prices file, Lure estimates the spend of the target, judge and attacker from the tokens each run used, and stops the batch before it passes `--max-cost` (exit code 3).

**You need.** A prices file. Lure ships no built-in prices: check every rate against your provider's price page.

**Set up.**

```bash
cp prices.example.yaml prices.yaml
```

Every model in a run needs a price, local ones too. List the Ollama model at 0:

```bash
printf '  llama3.1:8b:\n    input: 0\n    output: 0\n' >> prices.yaml
```

**Try it.**

```bash
lure run attacks/indirect_prompt_injection/lure-ipi-001.yaml --target ollama --model llama3.1:8b --prices prices.yaml --max-cost 0.50
```

You should see: `Spend: $0.00 (attacker $0.00, target $0.00, judge $0.00)`.

**Learn more.** [`run-in-your-environment.md`](run-in-your-environment.md#4-first-run-with-a-spending-cap).

## Policy file and CI gate

**What it does.** `lure.yaml` says which results fail the gate (for example any Fail at or above a severity, or any send outside your allowed domains). `lure run` and `lure report` apply it and exit 0 (pass), 1 (a run failed the policy), 2 (error) or 3 (stopped at the spending cap), so a CI job can block on it.

**You need.** Nothing extra: `lure.yaml` ships with the repository.

**Set up.** Read and adjust the policy, for example your own allowed domains:

```bash
nano lure.yaml
```

**Try it.** Gate saved runs without calling the model again:

```bash
lure report results/adaptive/ --out adaptive.html; echo "exit code $?"
```

You should see: `Policy: FAIL ...` and `exit code 1` if a run failed the policy (the adaptive run above often does), or `Policy: PASS` and `exit code 0`.

**Learn more.** [`usage.md`](usage.md#policy-and-ci), [`run-in-your-environment.md`](run-in-your-environment.md#6-sarif-and-the-ci-gate).

## Profiles

**What it does.** A profile describes your own agent: its system prompt, its model, and its tools mapped to Lure's mocks. `lure run --profile` runs the attacks those tools cover.

**You need.** Nothing extra. The example profiles for helpdesk, ops and sales run on Ollama's `llama3.1`.

**Set up.**

```bash
ollama pull llama3.1
```

Start your own from an example, then edit it:

```bash
cp profiles/example-helpdesk-agent.yaml profiles/my-agent.yaml
```

**Try it.**

```bash
lure run --profile profiles/example-helpdesk-agent.yaml
```

You should see: one line per attack the profile covers (`[1/3] lure-egr-005 run 1/1 ...`), a summary table and `Manifest: results/example-helpdesk-agent/<timestamp>/manifest.json`.

**Learn more.** [`writing-a-profile.md`](writing-a-profile.md), [`profiles.md`](profiles.md).

## Approval workflow

**What it does.** After a profile run, `lure report --approval` writes a one-page approval report, `lure decide` records approve or reject in an append-only log, `lure retest` reruns the suite and compares it with the approved run, and `lure status` answers "is this agent approved as it is now?" (exit 0 yes, 1 no).

**You need.** A profile run (see [Profiles](#profiles)).

**Set up.** Write the approval page for the run folder printed as `Manifest:` (replace `<timestamp>`):

```bash
lure report results/example-helpdesk-agent/<timestamp>/ --approval approval.html
```

Record the decision (it applies to the profile's latest run):

```bash
lure decide profiles/example-helpdesk-agent.yaml --decision approve --by "Security reviewer"
```

**Try it.**

```bash
lure retest profiles/example-helpdesk-agent.yaml
```

You should see: `Compared: with the approve decision of ...`, `Result: NO REGRESSION` (exit 0), or the attacks that regressed (exit 1). `lure status profiles/example-helpdesk-agent.yaml` then prints `Status: example-helpdesk-agent is approved ...`.

**Learn more.** [`profiles.md`](profiles.md#approval-report), [`vetting-workflow.md`](vetting-workflow.md).

## lure audit and the MCP allowlist

**What it does.** `lure audit` reads an agent's setup before any model call and reports what makes it unsafe: hardcoded secrets, auto-approve modes, risky tools with no confirmation step, unrestricted egress, MCP servers. The MCP allowlist in `lure.yaml` lists the servers your organization approved, and the audit fails on any other.

**You need.** Nothing extra. [gitleaks](https://github.com/gitleaks/gitleaks), when installed, adds its secret scan.

**Set up.** Nothing to set up for the example profiles. To approve MCP servers, add an `mcp:` block to `lure.yaml` (format in [`audit.md`](audit.md#the-mcp-server-allowlist)).

**Try it.**

```bash
lure audit profiles/example-helpdesk-agent.yaml
```

You should see: findings such as `[high] Risky tool with no confirmation step: ...`, each with a `fix:` line, and `Summary: 0 critical, 4 high, 0 medium, 0 info`. The exit code is 1 only on a critical finding.

**Learn more.** [`audit.md`](audit.md).

## Docker sandbox

**What it does.** `lure sandbox run` tests a real agent that runs its own tools, in a throwaway container per run: read-only, no capabilities, and no network except Lure's egress gateway, which blocks and logs every host but the model API.

**You need.** Docker, running. For an agent on a paid API, a separate key with a spend limit in `LURE_AGENT_API_KEY`, never your main key ([install guide](install.md#optional-the-docker-sandbox)).

**Set up.**

```bash
lure sandbox build
```

**Try it.**

```bash
lure sandbox run attacks/self_modification/lure-smo-005.yaml --profile profiles/example-ref-agent-local.yaml
```

You should see: `Sandbox: ... egress allowed to host.docker.internal:11434 ...`, a `Verdict:` line, and `Egress: 0 blocked, 0 DNS lookups, 0 decoy calls`.

**Learn more.** [`container.md`](container.md), [`usage.md`](usage.md#how-the-sandbox-works).

## Results store and dashboard

**What it does.** `lure store` indexes every saved run into one local DuckDB file you can query with SQL, and `lure serve` puts a local, read-only dashboard on top: runs, transcripts, approval pages and vetting history. Neither calls a model.

**You need.** The `store` extra, which installs DuckDB.

**Set up.**

```bash
pip install -e '.[store]'
```

```bash
lure store add
```

You should see: `results/lure.duckdb: indexed ...`

**Try it.**

```bash
lure store query "SELECT target, verdict, count(*) AS runs FROM runs GROUP BY 1, 2 ORDER BY 1, 2"
```

You should see: a table of runs per model and verdict. Then `lure serve` prints `Serving http://127.0.0.1:8765/`: open that address in your browser, and press Ctrl+C to stop.

**Learn more.** [`store-and-serve.md`](store-and-serve.md).

## Gitea pipeline

**What it does.** On a self-hosted Gitea, a private vetting repository holds each agent's profile, runs and decision log. Every decision is a reviewed pull request, and `lure status` runs as a required check in each tool's repository.

**You need.** A Gitea server with Actions runners, and a private vetting repository with Lure's files at its root. This was not tested end to end here: only the commands below were.

**Set up.** In the vetting repository, copy the workflows:

```bash
mkdir -p .gitea/workflows
```

```bash
cp docs/ci/gitea/lure-test.yml docs/ci/gitea/lure-retest.yml .gitea/workflows/
```

`docs/ci/gitea/approval-check.yml` goes in each tool's own repository instead.

**Try it.** The required check runs this; it works on your machine too:

```bash
lure status profiles/example-helpdesk-agent.yaml
```

You should see: `Status: example-helpdesk-agent is approved ...` (exit 0) after the [approval workflow](#approval-workflow) above, or `is not approved: no decision recorded ...` (exit 1).

**Learn more.** [`gitea-pipeline.md`](gitea-pipeline.md).

## Arcanum coverage

**What it does.** Every current attack carries codes from the Arcanum Prompt Injection Taxonomy (inputs, intents, techniques, evasions). `lure coverage` counts which codes the library tests and writes a Markdown table.

**You need.** Nothing extra.

**Set up.** Nothing to set up.

**Try it.** Write it to a new file (the default overwrites `docs/arcanum-coverage.md`):

```bash
lure coverage --out coverage.md
```

You should see: `Arcanum taxonomy v1.6.1 coverage of 72 current attacks:` with counts of inputs, intents, techniques and evasions tested, then `Wrote coverage.md`.

**Learn more.** [`arcanum-coverage.md`](arcanum-coverage.md).
