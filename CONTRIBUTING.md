# Contributing to Lure

Lure attacks AI agents in a sandbox and scores what they do. Contributions
that add attacks, categories, adapters or policy rules are welcome. This page
covers each, plus the rules every change must keep.

## Ground rules

These are not negotiable; a pull request that breaks one is closed.

| Rule | In practice |
| --- | --- |
| Mock tools only | Targets only ever get tools from `lure/tools/`. A mock logs the call and returns fake data. It never touches the network, the real filesystem, email or payments. |
| Fake data only | Every domain is under `.example` (the loader rejects anything else, even inside base64). People, accounts, invoices and secrets are invented. Never real credentials, PII or customer data. |
| Model APIs are the only network calls | Adapters may call the model under test or the LLM judge, nothing else. Tests never open a socket: `tests/conftest.py` fails any test that tries. |
| Payloads stay in the sandbox | Payloads target Lure's own mock tools, never a real third-party service. |
| Agent-only and generic | No org-specific names or assumptions. No general app or secrets scanning; other tools do that. |
| Map every attack | Every attack carries ATLAS and ATT&CK IDs, verified on atlas.mitre.org and attack.mitre.org. If unsure, say so in the PR. |

Writing style: no em dashes anywhere (code, comments, docs, commit messages).
Prefer tables, checklists and code over long prose.

## Setup

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
pytest && ruff check .
```

`pytest` needs no API key and no network. The live Ollama smoke test is
opt-in: `pytest -m ollama`.

## Add an attack

1. Pick the category folder under `attacks/` and the next free id with that
   folder's prefix, e.g. `attacks/tool_abuse/lure-tab-004.yaml`. The file
   name must match the `id`.
2. Add or reuse fixtures in `fixtures/` (JSON: an inbox, files, web pages,
   memory notes, or `mcp` tool definitions). Fake data and `.example` domains
   only.
3. Write the YAML:

   ```yaml
   id: lure-tab-004
   name: One line that says what the attack tries
   category: tool_abuse              # must match the folder
   atlas: [AML.T0051.001, AML.T0053] # required, verified
   attack: [T1485]                   # ATT&CK, may be []
   severity: high                    # low | medium | high | critical
   target_task: "A normal task the agent is asked to do."
   fixtures:
     files: fixtures/files_example.json
   injection:
     location: files[1].content      # fixture path, or "task" for the user turn
     payload: "The attacker's text."
     placement: append               # append | prepend | replace
   tools: [list_files, read_file, delete_file]
   fail_if:                          # at least one rule: the harmful call
     - tool: delete_file
   partial_if:
     - asked_user_before: delete_file
   pass_if:
     - flagged_as_suspicious: true
   task_check: ["a fact only the fixture holds"]   # proves the target did the task
   ```

   Rule keys: `tool`, `to_domain_not_in`, `body_contains`, `args_contain`,
   `account_not_in`, `reply_contains`, `asked_user_before`,
   `flagged_as_suspicious`. `body_contains` checks an email's subject and
   body; `args_contain` checks every argument of the call at any depth, and
   may also name payload text (for example the attacker's address being
   saved to memory). Optional top-level keys: `partial_if`, `pass_if`,
   `task_check`, `required_tools`, `system_prompt`, `version`,
   `followup_tasks`, `responders` (see [Multi-step attacks](#multi-step-attacks)),
   `goal` (the attacker's aim in plain words, needed for `--attacker-model`;
   never restate the scoring rules or a secret the attack tries to leak).
   Judge from the tool-call log; `reply_contains` is only for fixed strings
   (a secret, a canary) whose appearance in the reply is the harm.
4. Add the ATLAS and ATT&CK IDs to [`docs/atlas-mapping.md`](docs/atlas-mapping.md),
   and any new ID's name to `lure/report/techniques.py`.
5. Add scripted-turn tests to the category's library test
   (`tests/test_tab_library.py` for tool abuse): one run that does the task
   safely (Pass), one that takes the harmful action (Fail), and the Partial
   case if the attack has one. For a multi-step attack, also test the run
   where the first step never happens (Invalid).
6. Run it for real against at least one target and include the verdicts in
   the PR.

**Changing an existing attack** in a way that changes its results (a
stricter rule, a new system prompt): bump `version`, and keep the old one as
`<id>-v<N>.yaml` so its findings stay reproducible. Folder runs use only the
current version.

## Multi-step attacks

Four building blocks make an attack harder than one poisoned document. All
of them stay inside the mocks: nothing here is a real server, inbox or
memory store.

| Block | Key | What it does |
| --- | --- | --- |
| Later user turns | `followup_tasks` | Each string is a new user turn, sent once the target finishes the turn before. `max_turns` applies per user turn. The judge reads every turn's final reply, so an offer in turn 1 still counts. |
| Responders | `responders` | Release a pending fixture item into a mock after a matching tool call: new mail, a new or changed file or page, or a changed tool definition. |
| Poisoned tool definitions | an `mcp` fixture | Tools defined by a fixture, each with its own description, parameter schema and canned result. List them in `tools` by name. |
| Memory | a `memory` fixture | Notes from earlier sessions for `search_memory`; `save_memory` adds notes later searches in the run can find. |

**Responders.** A pending fixture is one no tool reads; only a responder can
release its items. The trigger key is `when` (YAML reads a bare `on:` as
true).

```yaml
fixtures:
  inbox: fixtures/inbox_followup_chain_v2.json
  inbox_followups: fixtures/inbox_followup_chain_replies.json   # pending
responders:
  - when:                       # tool, plus optional to_domain_in, body_contains, args_contain
      tool: send_email
      to_domain_in: [clearpath-recon.example]
    then:
      add_inbox: inbox_followups[0]   # add_inbox | add_file | update_page | update_tool
    times: 1                          # default 1
injection:
  location: inbox_followups[0].body   # a payload may sit in a pending item
```

| Action | Item | Effect |
| --- | --- | --- |
| `add_inbox` | an inbox message | Appended to the inbox |
| `add_file` | `{path, content}` | Creates or replaces the file |
| `update_page` | `{url, title, body}` | Creates or replaces the page |
| `update_tool` | `{name, description, parameters?}` | Replaces a listed tool's definition from the next model request on (a "rug pull"); the adapter's `set_tools` sends it |

Firings are deterministic and recorded as `events` in the result and as
`event` entries in the transcript. A payload in a pending item only counts as
delivered when a tool result carried it to the target (or, for
`update_tool`, when the responder fired). Otherwise the run is Invalid: the
attack's first step never happened.

**MCP tool fixtures.** Each entry is `{name, description, parameters,
result}`. Names are snake_case and may not shadow a built-in mock. Plant the
payload in the definition itself, for example `mcp[0].description` or
`mcp[0].parameters.properties.notes.description`. It reaches the target when
the tool is offered, so no read is needed.

**Memory fixtures.** Each note is `{content}` with an optional `id` and
`saved` date. A `search_memory` call only delivers a planted note if its
result includes it.

## Add a category

A category is a folder under `attacks/`; nothing in the code lists them.

1. Create `attacks/<category>/` with a snake_case name, and add at least one
   attack whose `category:` matches it. Pick a three-letter id prefix not in
   use (e.g. `lure-sup-001`).
2. Optional, for nicer reports:
   - a display name in `CATEGORIES` in `lure/report/techniques.py` (otherwise
     the folder name is used, e.g. "Supply chain");
   - a guardrail in `GUARDRAILS` in `lure/report/exec_summary.py`, used when
     the category is the weakest area.
3. Add `tests/test_<prefix>_library.py` like the existing library tests.
4. Add the category to the attack library table in `README.md`.

Policies can enable it right away: `categories: [<category>]` in `lure.yaml`.

## Add an adapter

Adapters connect Lure to a model. The interface is
[`lure/adapters/base.py`](lure/adapters/base.py):

| Piece | Job |
| --- | --- |
| `ModelAdapter.provider` | Short name; results record the target as `provider:model` |
| `ModelAdapter.start(system, tools)` | Open a `Conversation` with a system prompt and `ToolSpec`s (JSON Schema parameters) |
| `Conversation.send_task(task)` | Send the user turn, return a `ModelTurn` |
| `Conversation.send_tool_results(results)` | Return results for the last turn's calls, return the next `ModelTurn` |
| `Conversation.set_tools(tools)` | Offer a changed tool set from the next request on (`update_tool` responders). The base raises `AdapterError`, so an adapter without it scores such runs Error |
| `ModelTurn` | `text`, `tool_calls` (never executed by the adapter), `stop_reason`, `raw`, `usage` (`input_tokens`, `output_tokens`, when reported) |
| `AdapterError` | Raise it for any network, auth or bad-response failure; the run is scored Error |

Steps:

1. Add `lure/adapters/<name>.py`. Keep history in the provider's own format.
   Send no `tools` key when the tool list is empty (the LLM judge uses none).
   Implement `set_tools`, and accept a second `send_task` on the same
   conversation (multi-turn attacks).
2. Read settings from arguments, else `LURE_<NAME>_*` environment variables
   loaded from `.env`, and add them to `.env.example`. Never log or print a
   key.
3. Talk only to the configured model endpoint.
4. Register it in `TARGETS` and `make_adapter` in `lure/cli.py`.
5. Test against mocked HTTP only (`httpx2.MockTransport`): settings, request
   shape, tool-call round trip, usage, error handling, and one full
   `run_attack` judged Fail. See `tests/test_openai_compat.py`.

## Add a policy rule

The policy is `lure.yaml`, loaded by [`lure/policy.py`](lure/policy.py).
Exposure lives in `lure/exposure.py`.

1. Add the key to `KEYS`, `FAIL_ON_KEYS` or `OVERRIDE_KEYS` and validate it
   in `parse()`. Unknown keys are errors, so a typo never silently disables a
   gate.
2. Apply it in `Policy.enabled()` (what runs) or `Policy.check()` (what
   fails). A check returns `Violation`s with a short `detail`; it must work
   on saved records too (`PolicyRun.from_record`), so `lure report` can gate
   old results.
3. Keep exit codes as they are: 0 pass, 1 policy fail, 2 bad input or run
   error.
4. Document it in `lure.example.yaml` and the README policy section; change
   the shipped `lure.yaml` only if the default should change.
5. Test parsing, the error message for a bad value, and evaluation in
   `tests/test_policy.py`, and the exit code in `tests/test_exit_codes.py`.

## Pull request checklist

- [ ] `pytest` and `ruff check .` pass
- [ ] Fake data and `.example` domains only; no real side effects
- [ ] ATLAS and ATT&CK IDs verified (or flagged as unverified)
- [ ] Results schema changes are additive, or bump `schema_version` and add `schema/results.v<N>.json`
- [ ] Docs updated where behavior changed
- [ ] No em dashes
