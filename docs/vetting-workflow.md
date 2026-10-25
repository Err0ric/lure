# Weekly vetting workflow

How to approve an agent with Lure and keep the approval true: intake, test, decide, retest on change and every week, track. Each step is one command. Everything runs over Lure's mock tools: nothing the agent does is executed, sent or paid.

| Step | Who | Command | Output |
| --- | --- | --- | --- |
| 1. Intake | Agent owner | write `profiles/<name>.yaml` | The profile: prompt, tools, model |
| 2. Test | Tester | `lure run --profile` | `results/<name>/<timestamp>/` |
| 3. Decide | Approver | `lure report --approval`, then `lure decide` | `approval.html`, a line in `decisions.jsonl` |
| 4. Retest | Scheduler (cron or CI) | `lure retest` | A new run folder with `retest.json`; exit 1 on a regression |
| 5. Track | Approver | read `decisions.jsonl` and the retest output | The current decision and what changed since |

## Where the state lives

A retest needs the files of earlier steps, so keep them in one place that persists: a fixed machine, or a private repository that only the vetting team can read.

| File | Written by | Needed by | Note |
| --- | --- | --- | --- |
| `profiles/<name>.yaml` | Agent owner | every step | Holds the agent's real system prompt |
| `results/<name>/<timestamp>/` | `lure run`, `lure retest` | `lure decide`, `lure retest`, `lure report` | Each run folder has a `manifest.json`; keep at least the approved run |
| `vetting/<name>/decisions.jsonl` | `lure decide` | `lure retest` | Append-only; stores the run folder as given, so run every command from the same folder |
| `lure.yaml` | Security team | every step | Allowed outbound domains and the policy; its hash is recorded, and a change is listed by a retest |
| `prices.yaml` | Tester | `--max-cost` | Copy of `prices.example.yaml`, rates checked |

`profiles/`, `results/` and `vetting/` are gitignored in Lure's own repository, because they name real agents and hold their prompts. In a private vetting repository, commit them on purpose: remove those lines from its `.gitignore`.

## 1. Intake

The agent owner writes a profile: the agent's system prompt, each of its tools mapped to a Lure mock tool, the model it runs on, and what the chat app showing its output fetches by itself (`renders`). See [profiles.md](profiles.md) for the format and `profiles/example-ap-agent.yaml` for an example.

Intake checklist:

- [ ] The system prompt is the one the agent runs with, word for word.
- [ ] Every tool the agent has is listed, with its real name and description, and `maps_to` a Lure mock tool.
- [ ] Tools the agent cannot work without are marked `essential: true`.
- [ ] `renders` says whether the chat app shows remote images and link previews.
- [ ] The model and account are approved for the agent's prompt: the profile's prompt goes to the model API it names. For a work agent use an organization-approved account or a local model.
- [ ] `owner` names the team or role that owns the agent, not a person.

## 2. Test

```bash
lure run --profile profiles/example-ap-agent.yaml --repeat 3 \
  --prices prices.yaml --max-cost 2.00
```

Lure runs every attack the agent's tools cover, 3 times each, and skips the rest with the reason. Use at least `--repeat 3`: with fewer, the approval page is marked Preliminary and never recommends a plain Approve.

## 3. Decide

```bash
lure report results/example-ap-agent/<timestamp>/ \
  --out results/example-ap-agent/<timestamp>/report.html \
  --approval results/example-ap-agent/<timestamp>/approval.html
```

The approver reads `approval.html`: what the agent can access, what was tested, what went wrong, a recommended decision (rule-based, never a model) and suggested conditions. A person decides, then records it:

```bash
lure decide profiles/example-ap-agent.yaml --decision approve-with-conditions \
  --by "AP operations lead" \
  --conditions "Remove web_fetch." \
  --notes "Approval page of 2026-10-24 reviewed with the security team."
```

The decision is tied to the run folder (default: the latest) and to the profile hash it tested. If the profile changed after the run, `lure decide` refuses: test again first.

## 4. Retest on change and every week

```bash
lure retest profiles/example-ap-agent.yaml --prices prices.yaml --max-cost 2.00
```

`lure retest` reruns the last suite (same attacks and versions, variants, repeat, judge, attacker) under the profile as it is now, and compares the new run with the last approved run. Run it:

- **When the profile changes**: a new prompt, a tool added or removed, a new model.
- **When Lure or the policy changes**: new attack versions or a new `lure.yaml`.
- **Every week**, even with no change: the model behind an API name can change without notice.

| Exit | Meaning | Action |
| --- | --- | --- |
| 0 | No new failure | None. Conditions the retest verified are listed |
| 1 | A new failure (regression) | Tell the approver; the decision no longer holds until they decide again |
| 2 | A run errored, or bad input | Fix the setup and rerun |
| 3 | Stopped at `--max-cost` | Raise the cap or cut the suite; the comparison is partial |

After a retest that changes something, build its approval page (`lure report <new run folder> --approval ...`): it says what the retest found and which conditions it verified. A condition to remove a tool is verified once the tool is gone from the profile. A condition that a person confirms a tool's calls is held in Lure's test once the profile marks the tool `gated: true` and its gate held (see [profiles.md](profiles.md#confirmation-gates)); the approver confirms the real step on the sign-off.

### Cron (a fixed machine)

A weekly line, Mondays at 06:00, from the folder that holds `profiles/`, `results/` and `vetting/`. Mail on a nonzero exit goes to the crontab's `MAILTO`:

```cron
MAILTO=vetting-team@corp.example
0 6 * * 1  cd /srv/lure-vetting && .venv/bin/lure retest profiles/example-ap-agent.yaml --prices prices.yaml --max-cost 2.00 >> logs/retest.log 2>&1 || echo "lure retest failed with exit $?; see /srv/lure-vetting/logs/retest.log"
```

To also retest when the profile changes, a daily line can compare the profile's hash with the one its latest run tested, and retest only on a difference:

```cron
30 6 * * *  cd /srv/lure-vetting && ./retest-if-changed.sh profiles/example-ap-agent.yaml >> logs/retest.log 2>&1
```

`retest-if-changed.sh`, kept next to the profiles:

```sh
#!/bin/sh
# Retest a profile if it changed since its latest run. Exit as lure retest.
set -eu
profile="$1"
name=$(.venv/bin/python -c 'import sys, yaml; print(yaml.safe_load(open(sys.argv[1]))["name"])' "$profile")
last=$(ls -d "results/$name"/*/ 2>/dev/null | sort | tail -n 1)
[ -n "$last" ] || { echo "no run of $name yet: run lure run --profile first"; exit 2; }
now=$(shasum -a 256 "$profile" | cut -d ' ' -f 1)
tested=$(.venv/bin/python -c 'import json, sys; print(json.load(open(sys.argv[1]))["profile"]["sha256"])' "${last}manifest.json")
[ "$now" = "$tested" ] && exit 0
.venv/bin/lure retest "$profile" --prices prices.yaml --max-cost 2.00
```

Runs live under `results/<name>/`, where `<name>` is the profile's `name:`.

### GitHub Actions (a private vetting repository)

[`ci/lure-retest.yml`](ci/lure-retest.yml) runs `lure retest` every Monday, on every push that changes a profile or `lure.yaml`, and by hand. It fails the job on a regression and keeps the new run folder and approval page as a job artifact. It does not record decisions or commit run folders: the approver does that after reading the page, so every line in the decision log comes from a person.

On a self-hosted Gitea, the same flow runs as reviewed pull requests, with `lure status` as each tool repository's required check: [gitea-pipeline.md](gitea-pipeline.md).

After a job, the approver downloads the artifact, reads `approval.html`, and if they decide again, copies the run folder into `results/<name>/`, runs `lure decide ... --run results/<name>/<timestamp>` and commits both.

## 5. Track

`vetting/<name>/decisions.jsonl` is the record: one JSON line per decision with the date, decision, role, conditions, run folder, profile hash, model and Lure version. Nothing is edited; a later line supersedes an earlier one.

```bash
tail -n 1 vetting/example-ap-agent/decisions.jsonl
```

Weekly review, about 10 minutes per agent:

- [ ] The last retest exited 0. If not, the approver has seen its approval page.
- [ ] The latest decision matches the profile in use: `lure decide` refuses a mismatched run, and a retest lists a profile hash change under Changed.
- [ ] Every condition of the latest approve-with-conditions decision is verified, or has an owner and a date.
- [ ] A reject is still in force: the agent is not deployed.
- [ ] New Lure attacks since the approved run: rerun with `lure run --profile` (a retest repeats the old suite only) and decide again if anything fails.
