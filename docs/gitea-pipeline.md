# Vetting agents on Gitea

A pull-request approval flow on a self-hosted Gitea: a private vetting repository holds each agent's profile, its test runs and the decision log, and every decision is a reviewed pull request. Each tool's own repository then checks, as one of its required checks, that its agent is approved as it is now.

Everything runs on your Gitea Runners. With the local Ollama option, no prompt, payload or reply leaves your network. Lure's mock tools never touch a real system either way.

The workflow examples are in [`ci/gitea/`](ci/gitea/): [`lure-test.yml`](ci/gitea/lure-test.yml), [`lure-retest.yml`](ci/gitea/lure-retest.yml) and [`approval-check.yml`](ci/gitea/approval-check.yml). The steps behind them are in [vetting-workflow.md](vetting-workflow.md).

## Two repositories

| Repository | Holds | Who can merge | Workflows |
| --- | --- | --- | --- |
| Vetting (private), for example `security/agent-vetting` | Lure's files at the root, `profiles/`, `results/<name>/<timestamp>/` (approved runs), `vetting/<name>/decisions.jsonl`, `lure.yaml`, `prices.yaml` | The security team, through reviewed pull requests | `lure-test.yml` on pull requests, `lure-retest.yml` weekly and on change |
| Each tool | The agent's code, and optionally its system prompt file | Its own team | `approval-check.yml`: a required check that runs `lure status` against the vetting repository |

In the vetting repository, remove `profiles/`, `results/` and `vetting/` from `.gitignore`: there they are committed on purpose. Keep the repository private: profiles hold real system prompts.

## The approval flow

1. **Propose.** The agent's owner opens a pull request in the vetting repository that adds or changes `profiles/<name>.yaml` ([writing-a-profile.md](writing-a-profile.md)).
2. **Test.** `lure-test.yml` runs `lure run --profile --repeat 3` with a spend cap for each changed profile, and attaches an artifact with each profile's `approval.html`, report and run folder.
3. **Review.** The approver (a code owner of `vetting/`) downloads the artifact and reads the approval page.
4. **Decide, in the same pull request.** The approver copies the run folder from the artifact to the same path, records the decision and pushes both:

   ```bash
   cp -R ~/Downloads/lure-approval/results/<name>/<timestamp> results/<name>/
   lure decide profiles/<name>.yaml --decision approve-with-conditions \
     --by "Security lead" --run results/<name>/<timestamp> \
     --conditions "Require a person's approval before erp_pay_invoice makes any payment."
   git add results/<name>/<timestamp> vetting/<name>/decisions.jsonl
   git commit -m "Approve <name> with conditions"
   ```

   `lure decide` refuses a run of a different profile version, so the decision always names the profile file under review.
5. **Merge.** Branch protection requires the code owner's approval, so a change to `vetting/` merges only with the security team's review. A reject is recorded and merged the same way: it is part of the record.
6. **Gate.** From then on, each tool's `approval-check` job passes only while the latest decision on the vetting repository's main branch approves the profile, and the profile (and its prompt file) is unchanged since.
7. **Retest.** `lure-retest.yml` reruns every approved profile every Monday and on every push to `profiles/` or `lure.yaml`, and fails on a new failure against the approved run. The approver reads the new pages and decides again, in a new pull request.

## `lure status`

```bash
lure status profiles/<name>.yaml        # --vetting-dir vetting by default
```

| Exit | When | Prints |
| --- | --- | --- |
| 0 | The latest decision is approve or approve-with-conditions, and the profile file's SHA-256 is the one that decision was about | The decision, who made it, the date, the conditions |
| 1 | The latest decision is a reject, there is no decision, or the profile changed since it was approved | Which of the three, with both hashes for a change |
| 2 | The profile or the decision log cannot be read | The error |

The latest decision wins: a reject after an approval fails the check, and a new approval after a reject passes it. A profile's hash covers the profile file and its `system_prompt_file`, so any change to either needs a retest and a new decision.

## CODEOWNERS

Gitea reads the first of `CODEOWNERS`, `docs/CODEOWNERS` and `.gitea/CODEOWNERS`. Unlike GitHub, each rule is a Go regular expression, not a glob:

```text
# .gitea/CODEOWNERS in the vetting repository
^vetting/.*                  @security/agent-approvers
^profiles/.*                 @security/agent-approvers
^lure\.yaml$                 @security/agent-approvers
^\.gitea/.*                  @security/agent-approvers
```

Owners are requested as reviewers automatically. Owning `.gitea/` too stops a pull request from weakening the workflows that test it.

## Branch protection

On the vetting repository's main branch:

| Setting | Value | Why |
| --- | --- | --- |
| Disable push | On | Every change goes through a pull request |
| Required approvals | 1 or more | |
| Restrict approvals to allowlisted users or teams | `security/agent-approvers` | Only approvers' reviews count |
| Code-owner reviews required before merging | On (Gitea 28 and later) | Blocks merging until every matching CODEOWNERS rule is approved by one of its owners. On earlier versions, use "Block merge on official review requests" with CODEOWNERS |
| Dismiss stale approvals | On | A commit after the review, such as an edited decision, needs a fresh review |
| Block merge on rejected reviews | On | |
| Protected file patterns | `vetting/**;profiles/**;lure.yaml` | These files cannot be changed directly, even by people who can write to the branch |
| Administrators must follow branch protection rules | On | No force merge around the review |
| Enable status check | Optional, see below | |

Do not make `lure-test` a required check here. A failing test is often what leads to a reject, and the reject still has to merge to be on record. The code owner's review is the gate, and the approval page is what it reviews.

## In a tool's repository

Copy [`approval-check.yml`](ci/gitea/approval-check.yml) to the tool repository's `.gitea/workflows/` and set:

| Setting | Where | Value |
| --- | --- | --- |
| `VETTING_REPO`, `PROFILE` | The workflow's `env` | The vetting repository, and this tool's profile in it |
| `VETTING_TOKEN` | Repository secret | A token that can only read the vetting repository, for example a bot user's token with read access to repositories. The job token cannot read another private repository |
| `PROMPT_FILE`, `PROFILE_PROMPT` | The workflow's `env`, optional | If the agent's prompt lives in this repository: this file, and the profile's `system_prompt_file` in the vetting repository |

Then make it a required status check in the tool repository's branch protection, next to its own tests: enable the status check and add a pattern matching the job's context. Gitea matches the pattern as a glob against the context name the runner reports, so copy the exact name from the list of recent checks, or use a glob such as `Agent approval*`.

How it ties into the tool's other checks:

- **Merging.** With `approval` required, a pull request in the tool repository cannot merge while its agent is unapproved, even if every other check passes.
- **Prompt changes.** With `PROMPT_FILE` set, the job copies this repository's prompt over the vetting repository's copy before `lure status`. A pull request that edits the prompt fails the check ("the profile changed since it was approved") until the vetting repository has a new approval of that prompt. Tool names and descriptions are not compared this way: they change in the profile, through the vetting repository.
- **Deploying.** If deploys run from Actions, add the deploy job to `approval-check.yml` with `needs: approval`, so a rejection or a later retest failure stops the next deploy too, not only the next merge:

  ```yaml
  jobs:
    approval:
      # ... the steps from approval-check.yml
    deploy:
      needs: approval
      if: gitea.event_name == 'push'
      runs-on: ubuntu-latest
      steps:
        - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.3.1
        - run: ./deploy.sh
  ```

- **After a retest regression,** the approver records a reject or a new decision in the vetting repository; every tool's next check reflects it. `lure status` reads the main branch as it is now, not as it was when the tool's pull request opened.

## Keeping prompts on your network

Set `LURE_OLLAMA_URL` as a repository or organization variable (for example `http://ollama.internal:11434`), give profiles `target: ollama`, and use a local judge that differs from the target. In `lure-test.yml`, Option B shows the command:

```bash
lure run --profile "$profile" --repeat 3 \
  --target ollama --model llama3.1:8b \
  --judge llm --judge-target ollama --judge-model llama3.1:70b
```

Leave `ANTHROPIC_API_KEY` out of these jobs entirely. A retest uses the profile's target and the judge its approved run used. The runner's job containers need a route to the Ollama server, and nothing else. `--max-cost` needs a rate for every model: list local models at 0 in `prices.yaml`, or leave the cap off for local runs.

## Gitea compared with GitHub Actions

Checked against Gitea's documentation and source on 2026-10-25.

| Topic | On Gitea |
| --- | --- |
| Workflow folder | `.gitea/workflows/`. Gitea reads `.github/workflows/` only when `.gitea/workflows/` does not exist (both are set by `[actions] WORKFLOW_DIRS`) |
| Runner | Gitea Runner (formerly act_runner), registered to your instance. `runs-on` must match labels a runner registered with; a job with several labels needs a runner with all of them |
| Actions | `uses:` without a host fetches from github.com by default (`[actions] DEFAULT_ACTIONS_URL`). Without a route out, mirror the actions to your instance and set it to `self`, or write absolute `https://<your-gitea>/...` URLs |
| Artifacts | The official `actions/upload-artifact@v4` and later treats Gitea as GitHub Enterprise Server and stops; the examples use v3.2.2-node20. `gitea.com/actions/gitea-upload-artifact` is a v4 copy that allows Gitea |
| Step summary | No step summary on older Gitea versions and runners. The examples write none; the approval page is the artifact |
| Contexts | `gitea.*` works like `github.*` (the examples use `gitea.base_ref` and `gitea.server_url`) |
| Tokens and permissions | The job token is `GITEA_TOKEN`; `permissions` limits it, within repository and owner settings. It cannot read another private repository, hence `VETTING_TOKEN` |
| Schedules | Cron as on GitHub, plus `@weekly` and the other shorthands |
| Actions per repository | New repositories start with Actions off: enable it in the repository's settings |

The examples pin every action to the commit of a Node 20 release (checkout v4.3.1, setup-python v5.6.0, upload-artifact v3.2.2-node20), for runner images that may not have Node 24. Update the pins together.
