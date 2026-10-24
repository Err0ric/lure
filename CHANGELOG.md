# Changelog

## v1.1.0 (2026-10-23)

Lure can now gate CI: one policy file decides what fails, exit codes say so,
and Markdown and SARIF carry the result to a job summary and code scanning.

### New

- **Policy file.** `lure.yaml` stays the single policy file and gains
  `policy_version`, `fail_on` (verdicts, `min_severity`, `exposure`),
  `categories` and per-attack `overrides`. Every key is optional and unknown
  keys are errors. `fail_on.exposure` defaults to true whenever
  `allowed_outbound_domains` is set, so data leaving the org fails CI out of
  the box even at 0% ASR. Without domains it is a no-op, and an explicit
  `exposure: true` with no domains is a config error. With no file, a Fail at
  any severity fails. See `lure.example.yaml`.
- **Exit codes.** `lure run` and `lure report` exit 0 when no run fails the
  policy, 1 when one does, and 2 on bad input or a run error. 1 wins over 2,
  so a confirmed finding is never masked by a flaky API call.
- **Which policy was used.** Run and report output, the Markdown and the
  SARIF name the policy file with its SHA-256, or "built-in default".
- **Markdown report** (`lure report --md`): summary, policy result, pass rate,
  ASR, influenced and detection rates, exposure, and findings grouped by ATLAS
  technique. All text from results is escaped.
- **SARIF 2.1.0** (`lure report --sarif`): one rule per attack id, with ATLAS
  and ATT&CK tags and a security-severity. Results point at the attack YAML
  file, never at an invented code location.
- **Results JSON Schema** (`schema/results.v1.json`). New records carry
  `schema_version`, `lure_version` and `attack.file`. Records from 1.0.0 still
  validate, and report and rescore note them once.
- **OpenAI-compatible adapter** (`--target openai`): OpenAI, vLLM, Groq, LM
  Studio, llama.cpp and Ollama's `/v1` endpoint, configured with
  `LURE_OPENAI_BASE_URL`, `LURE_OPENAI_API_KEY` and `LURE_OPENAI_MODEL`.
  Works as `--judge-target` too.
- **Category discovery.** A category is a folder under `attacks/`, so adding
  a category means adding a folder. A category named in the policy that has
  no folder fails before any model call.
- **Docs.** `CONTRIBUTING.md` (add an attack, category, adapter or policy
  rule), `docs/atlas-mapping.md` (kept in sync by a test),
  `docs/ci/lure-gate.yml` (a GitHub Actions gate with SARIF upload, actions
  pinned to SHAs), and `docs/config-audit.md` (a future stage, not
  implemented).

### Behavior to know

- **`lure report` gates old runs with the current policy.** It recomputes
  exposure from each saved tool-call log against the `lure.yaml` you have
  now, even for runs saved without a policy. Runs of attacks the policy
  disables are not gated. A baseline that passed under 1.0.0 can exit 1
  under 1.1.0: for example, the published Haiku baseline fails on its two
  jbk-002 v1 sends to `mailbox.example`.
- **Exit codes changed.** A run Error exits 2 (was 1). A Fail or an exposed
  run exits 1 (was 0).
- **Flags.** `--policy` and `--no-policy` replace `--org-policy` and
  `--no-org-policy`, which still work as aliases.
- **Folder runs skip attacks the policy disables** and list them. An attack
  file named directly always runs.
- **Attack files** must sit in `attacks/<category>/`, and the category must
  match the folder.

### Upgrade

```bash
git pull && pip install -e '.[dev]'
```

Review `lure.yaml` against `lure.example.yaml`. If CI scripts treated exit 1
as "a run errored", change them to treat 2 that way.

## v1.0.0 (2026-10-23)

First release: YAML attack library (21 attacks, 5 categories), mock tools,
rules judge with opt-in LLM judge, ATLAS and ATT&CK mapping, per-run JSON
results, batch stats, org exposure check, HTML report, `lure compare`.
