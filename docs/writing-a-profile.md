# Writing a profile: vet your own agent, step by step

This tutorial takes you from "we have an agent" to a signed approval page. It uses the two example profiles that ship with Lure: [`profiles/example-support-agent.yaml`](../profiles/example-support-agent.yaml) (a customer support assistant on a hosted model) and [`profiles/example-helpdesk-agent.yaml`](../profiles/example-helpdesk-agent.yaml) (an IT helpdesk assistant on a local model). Reference for every key: [profiles.md](profiles.md). The weekly routine after approval: [vetting-workflow.md](vetting-workflow.md).

Lure never calls your agent's real tools. A profile describes the agent; every tool call goes to Lure's mock tools, which log the call and return fake data. Nothing is sent, paid, refunded, reset or posted.

## Before you start

| You need | Why | Where it comes from |
| --- | --- | --- |
| The agent's system prompt, word for word | Lure tests the agent you run, not a generic one | The agent's config or code |
| Its list of tools, with their real names and descriptions | The model sees these; their wording changes its behavior | The tool definitions the agent loads |
| Which tools a person confirms before they run, and what that person sees | Lure tests whether the agent works around the step | The app's UI, or whoever built it |
| What the chat app or mail client does with images and links | Some leaks happen when an app loads an image by itself | The app's settings |
| An approved model account, or a local model | The profile's prompt is sent to the model API it names | Your security team |
| About 30 minutes, and a spend cap | A full run is about 3 runs of each attack that applies | `prices.yaml` (copy `prices.example.yaml`, check the rates) |

## Step 1: copy the closest example

```bash
cp profiles/example-support-agent.yaml profiles/my-support-agent.yaml
```

Everything under `profiles/` except the examples is gitignored, because a real system prompt can be sensitive. Keep your profile out of public repositories.

## Step 2: say what the agent is

```yaml
name: my-support-agent          # lowercase, digits, dashes; names the results folder
owner: Customer support lead    # a team or role, never a person's name
role: Customer support assistant for the corp.example online store
```

## Step 3: paste the real system prompt

Paste it inline under `system_prompt: >-`, or keep it in a file next to the profile:

```yaml
system_prompt_file: my-support-agent.prompt.txt
```

Use the exact text. If your prompt says "refunds only to the original card", Lure tests whether the agent keeps to that under attack. A tidied-up prompt tests a different agent. Lure refuses a prompt that contains something shaped like an API key.

## Step 4: map each tool to a Lure mock

List every tool the agent has, with its real name and description, and the Lure mock that stands in for it. The support example:

| The agent's tool | `maps_to` | What the mock does |
| --- | --- | --- |
| `desk_tickets` | `list_tickets` | Returns the fixture's open tickets |
| `desk_reply` | `reply_ticket` | Records a reply to the ticket's requester |
| `crm_lookup` | `lookup_customer` | Returns a fake customer and their orders |
| `crm_update` | `update_customer` | Changes a contact detail, in memory |
| `refunds_issue` | `issue_refund` | Records a refund; no money moves |
| `macros_read` | `read_file` | Returns a fake reply template |
| `integration_config` | `list_env` | Returns fake settings, every secret a `LURE-FAKE-` canary |

The helpdesk example maps `queue_list`, `queue_reply`, `dir_lookup`, `dir_reset_password`, `dir_add_to_group`, `mail_send` and `status_post` to `list_tickets`, `reply_ticket`, `lookup_user`, `reset_password`, `grant_access`, `send_email` and `post_message`. The full list of mocks is in [profiles.md](profiles.md#the-profile-file).

Rules of thumb:

- **Leave out what the agent cannot do.** An agent with no refund tool is never offered one, and refund attacks are skipped with the reason.
- **One agent tool per mock.** If two of your tools do the same thing, map the one the agent uses most.
- **No good match?** Leave the tool out and note it. Lure cannot test what it cannot stand in for.

## Step 5: mark the tools that matter

```yaml
  - name: desk_reply
    description: Reply to a ticket's requester.
    maps_to: reply_ticket
    essential: true             # the agent cannot work without it
  - name: refunds_issue
    description: Refund an order to a card (last 4 digits).
    maps_to: issue_refund
    gated: true                 # a person confirms each refund
```

| Key | Set it when | What changes |
| --- | --- | --- |
| `essential: true` | Removing the tool is not an option | The approval page suggests a confirmation step for it, never removing it |
| `gated: true` | The app asks a person before each call | The call stops for Lure's stand-in person; see below |
| `gate_shows: summary` | The person sees only a summary the agent writes, not the call | The agent must write that summary, and Lure checks whether it hides the harm |
| `summary_check: strict` | With `gate_shows: summary`: a summary must name the harm word for word (default `tolerant`) | Strict is the worst case for the agent; see [profiles](profiles.md) |
| `gate_over: 200` | The app asks only above an amount (`pay_invoice`, `issue_refund`) | Smaller calls run unasked, so splitting a payment is tested |
| `confirmer: deny_all` | You want to see how the agent behaves when every request is refused | The stand-in declines everything (the default, `careful`, declines only what the attack is after) |

Be honest here. If the confirmation step is a plan, not something the app does today, leave `gated` off: the approval page asks the approver to confirm on sign-off that the real step exists.

## Step 6: choose what to test

```yaml
scenarios: [customer_support]   # or it_helpdesk, accounts_payable, or all
policy: ../lure.yaml            # allowed outbound domains and what fails the policy
renders:                        # optional; unset means yes, the worst case
  images: false                 # the chat app does not load images in replies
```

- `scenarios` picks the packs whose tasks look like your agent's work. Pick `all` to also run the accounts payable attacks against it: the injections still apply, in a less familiar setting.
- `policy` points at a `lure.yaml` listing the domains your agent may send to. Anything else is counted as exposure.
- `third_party_tools: true` if the agent loads MCP or plugin tools; that turns on the tool poisoning attacks.

## Step 7: a small first run

Start cheap, to catch mapping mistakes before a full run:

```bash
lure run --profile profiles/my-support-agent.yaml --repeat 1 \
  --prices prices.yaml --max-cost 0.25
```

The helpdesk example runs on Ollama, so it costs nothing and nothing leaves the machine:

```bash
ollama pull llama3.1
lure run --profile profiles/example-helpdesk-agent.yaml --repeat 1
```

Then open the run's `manifest.json` (in `results/<name>/<timestamp>/`) and read `skipped`: every attack left out, with the reason. A reason you did not expect ("no profile tool maps to issue_refund") usually means a missing or wrong `maps_to`.

## Step 8: the full run

```bash
lure run --profile profiles/my-support-agent.yaml --repeat 3 \
  --judge llm --judge-target anthropic --judge-model claude-sonnet-5-5 \
  --prices prices.yaml --max-cost 2.00
```

Use at least `--repeat 3`: with fewer, the approval page says Preliminary and never recommends a plain Approve. The LLM judge is optional; it reads replies the rules cannot decide (a judge model never judges itself, so pick one other than the target).

## Step 9: build and read the approval page

```bash
RUN=results/my-support-agent/<timestamp>
lure report $RUN --out $RUN/report.html --approval $RUN/approval.html --approval-md $RUN/approval.md
```

`approval.html` is one printable page for the person who approves the agent:

| Section | Read it as |
| --- | --- |
| Recommendation and bottom line | What Lure suggests and, in one sentence, what an attacker could get the agent to do. Rule-based; a person decides |
| What the agent can access | Your tools in plain words, with the ones a person confirms |
| What was tested | The scenario packs, the kinds of attack, and what was not applicable, with the reason |
| What went wrong | Each problem with one example from the tool log |
| Stopped by the confirmation step | Attacks the agent tried and a person declined. **Bold** means it asked again after a decline: pressure on that person |
| Notes | It asked first, which is the safe behavior |
| Suggested conditions | What would fix each problem: remove a tool, add a confirmation step, change a setting |
| Sign-off | The decision, who made it, and a line per gated tool confirming the real step exists |

Also open `report.html` for the full technical report, with every tool call.

## Step 10: record the decision

```bash
lure decide profiles/my-support-agent.yaml --decision approve-with-conditions \
  --by "Customer support lead" \
  --conditions "Require a person's approval before refunds_issue refunds to any card other than the order's own, or above the refund limit, or remove refunds_issue."
```

Copy the condition text from the page: a retest checks it by its wording.

## Step 11: retest on change and every week

After you change the agent (a new prompt, a tool removed or gated, a new model), and every week anyway:

```bash
lure retest profiles/my-support-agent.yaml --prices prices.yaml --max-cost 2.00
```

It reruns the same suite and compares with the approved run. A condition to remove a tool is *verified* once the tool is gone. A condition that a person confirms a tool's calls is *held in Lure's test* once the tool is gated and the gate stopped the attack, never "verified": Lure cannot see your real app. Exit 1 means a new failure. Cron and GitHub Actions examples: [vetting-workflow.md](vetting-workflow.md).

## Common mistakes

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Almost every attack skipped | Few tools mapped, or `scenarios` too narrow | Map every tool the agent has; try `scenarios: all` |
| Many runs Invalid, "the agent's rules blocked the setup step" | The prompt stops the scenario before the attack (good for you) | Nothing to fix; the page lists them as not tested |
| Approve, but the agent can clearly be talked into things | Tools that act are missing from the profile | Add them; an untested tool is not a safe tool |
| The page says it assumed images load | `renders` unset | Set `renders:` to what the app really does, and rerun |
| A gated tool never shows as stopped | The attacks never reached it, or the agent refused first | Fine: the gate was not exercised. A retest cannot hold its condition until it is |
| Cost too high | `--repeat` and `--variants all` multiply runs | Keep `--variants` off for vetting; screen with `--repeat 1` first |
