# Security policy

Lure attacks AI agents on purpose, so its own safety rules are the product: mock tools only, no real side effects, fake data only, and model APIs as the only network calls. A way to break one of those rules is a vulnerability in Lure. Please report it privately.

## Report a vulnerability

Use GitHub's private vulnerability reporting: https://github.com/Err0ric/lure/security/advisories/new (the repository's Security tab, then "Report a vulnerability"). Only the maintainers see the report.

Please do not open a public issue, pull request or discussion for a vulnerability.

A useful report has:

- The Lure version (`lure --version`) and how you installed it
- What you did: the command, profile, attack file or fixture, with real secrets and prompts removed
- What happened and what you expected, ideally with the run's result JSON or tool-call log
- Whether it needs a malicious attack file, fixture or profile, or happens with Lure's own files

Lure is maintained by a small team. You can expect an acknowledgement within 7 days and an assessment within 30. We will agree a disclosure date with you, credit you in the release notes unless you prefer not, and publish a GitHub security advisory for confirmed issues.

## Supported versions

Fixes go into the latest release only. Upgrade to get them.

| Version | Supported |
| --- | --- |
| Latest release (currently 1.12.x) | Yes |
| Earlier releases | No |

## In scope

Anything that lets a test run, or Lure's own tooling, do something its safety rules say it never does:

| Area | Examples |
| --- | --- |
| Mock tools | A tool call reaching the real filesystem outside the run, the network, email, payments or a shell; a fixture or attack file that makes a mock do so |
| Network | Any connection other than the model API calls an adapter makes to the target or judge; an attacker or judge payload causing one |
| Fake data checks | A real domain, key or secret passing the loader's `.example` and `LURE-FAKE-` checks |
| Secrets | API keys from `.env` written into results, reports, logs, SARIF or the store |
| Reports and the dashboard | Attack text in a report, approval page or `lure serve` page that runs script, loads a remote resource or escapes HTML escaping; `lure serve` answering a non-local host or a request with another `Host` header, accepting a write, or passing request input into SQL |
| Results store | A `lure store query` or dashboard query that installs or loads a DuckDB extension, turns external access back on, or writes outside the store |
| CI examples | A workflow in `docs/ci/` that exposes a secret to a pull request from a fork or to a command line |
| Container | The image running as root, or holding a secret at build time |

## Out of scope

- **The attacks themselves.** Files in `attacks/` and `fixtures/` are prompt injection payloads by design, aimed at Lure's mock tools. An agent following them during a test is a finding about that agent, not a Lure vulnerability.
- **Model behavior.** A model that fails an attack, refuses it or leaks a canary is what Lure measures. Report those to the model's provider if you think they matter.
- **Your own profiles and fixtures.** Lure sends a profile's system prompt to the model API the profile names. Choosing that API is the profile owner's decision (see [`docs/profiles.md`](docs/profiles.md)).
- **Judge manipulation by a target's reply.** It is a documented limitation with bounded impact (the LLM judge never produces a Fail); see [How a run is scored](docs/usage.md#how-a-run-is-scored).
- **Findings in third-party dependencies** with no Lure-specific impact: report them upstream.

## Safe testing

Test against your own installation, with mock tools and `.example` data, as Lure intends. Do not test against systems or accounts you do not own, and do not send real customer data or credentials through a model API to prove a point.
