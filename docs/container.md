# Run Lure in a container

The [`Dockerfile`](../Dockerfile) builds an image with Lure, its attack library, fixtures, the example profiles and the shipped `lure.yaml`. It runs as a non-root user (uid 10001), its base image is pinned by digest, and it holds no secrets: API keys come in at run time and results go to a folder you mount.

The container is a convenient, tidy place to run Lure. It is not what keeps a mock-tool test safe: Lure's mock tools are. See [How the sandbox works](usage.md#how-the-sandbox-works). To test a real agent that runs as code, use the sandbox instead: [Run a real agent in the sandbox](#run-a-real-agent-in-the-sandbox).

## Build

```bash
docker build -t lure:1.14.2 .
```

`.dockerignore` keeps `.env`, `results/`, `vetting/` and every profile except the examples out of the build context, so they can never end up in an image layer.

## Run

Rules-only work needs no network at all, so turn it off:

```bash
# Rescore or report saved runs: no model is called.
docker run --rm --network none \
  -v "$PWD/results:/work/results" \
  lure:1.14.2 report results/my-run/ --out results/my-run/report.html
```

A run against a hosted model passes the key at run time, never at build time:

```bash
docker run --rm --env-file .env \
  -v "$PWD/results:/work/results" \
  lure:1.14.2 run attacks/indirect_prompt_injection/lure-ipi-001.yaml --target anthropic
```

Your own profile, mounted read-only with its policy:

```bash
docker run --rm --env-file .env \
  -v "$PWD/profiles/my-agent.yaml:/work/profiles/my-agent.yaml:ro" \
  -v "$PWD/results:/work/results" \
  lure:1.14.2 run --profile profiles/my-agent.yaml --repeat 3 \
    --prices prices.example.yaml --max-cost 1.00
```

Copy `prices.example.yaml` to your own `prices.yaml`, check the rates, and mount it the same way.

A local model on the host, so prompts never leave the machine:

```bash
docker run --rm -e LURE_OLLAMA_URL=http://host.docker.internal:11434 \
  -v "$PWD/results:/work/results" \
  lure:1.14.2 run attacks/ --target ollama --model llama3.1:8b
```

On Linux, add `--add-host host.docker.internal:host-gateway`.

## Hardening flags

Lure needs no extra privileges, so drop them all:

```bash
docker run --rm --read-only --tmpfs /tmp \
  --cap-drop ALL --security-opt no-new-privileges \
  --env-file .env -v "$PWD/results:/work/results" \
  lure:1.14.2 run attacks/ --target anthropic --model claude-haiku-5-5
```

| Flag | Why |
| --- | --- |
| `--read-only --tmpfs /tmp` | The image's files cannot change; Lure writes only results (the mount) and temporary files |
| `--cap-drop ALL`, `--security-opt no-new-privileges` | No Linux capabilities, and no way to gain any |
| `--network none` | For report, rescore, compare, coverage, store and status: none of them calls a model |
| `--env-file .env` | Keys stay in your `.env`, out of the image and out of `docker inspect` of the image |

A container cannot limit its network to the model API by itself. If you need that, put it on a network whose only route out is an egress proxy that allows the model API's host: that is what `lure sandbox run` does for an agent under test (below).

## Run a real agent in the sandbox

`lure sandbox run` tests an agent that runs as code, with its own tools, in a throwaway container per run. How it is isolated, what it records and its limits: [How the sandbox works](usage.md#container-isolation-for-real-agents).

### Build the images

```bash
lure sandbox build          # lure:<version> (gateway) and lure-ref-agent:<version>
```

Both are built from this checkout on the pinned base image; Lure pulls nothing else. The reference agent (`docker/agent.Dockerfile`, `lure/sandbox/refagent/`) is a tiny coding agent written for Lure with Python's standard library, no third-party agent code. Its tools are real (list, read and write files in `/workspace`, run shell commands, read and change its own settings in `/workspace/.agent/settings.json`), so it shows what the container holds. Like real coding agents, it loads `AGENTS.md` and the profile's `instruction_files` from its working directory into its system prompt at startup (`agent.load_instructions`, default `true`), so a downloaded instruction file reaches it whether or not the model would have opened it. pip is removed from its image, and `npm`, `npx`, `pip`, `pip3`, `curl`, `wget` and `git` are decoys.

### The profile

An agent profile is an ordinary profile plus an `agent:` block and `isolation:`:

```yaml
isolation: container          # or vm; Lure refuses an agent: block without one
agent:
  image: lure-ref-agent:1.14.2
  provider: anthropic         # or ollama: how the reference agent talks to its model
  model_url: https://api.anthropic.com   # its host:port is the one destination allowed
  env: [LURE_AGENT_API_KEY]   # names inherited from your environment, never values
  # allow: [extra.host.example:443]      # more allowed host:port, if the agent needs one
  # limits: {memory: 512m, cpus: "1.0", pids: 128, workspace: 64m}
```

[`profiles/example-ref-agent.yaml`](../profiles/example-ref-agent.yaml) uses Anthropic; [`profiles/example-ref-agent-local.yaml`](../profiles/example-ref-agent-local.yaml) uses Ollama on the host (`host.docker.internal:11434`), so nothing leaves the machine. Ollama's API is unauthenticated and can pull, create and delete models, so for `provider: ollama` over plain HTTP the gateway allows only `/api/generate` and `/api/chat` (never pull, push, create, copy or delete; a CONNECT tunnel to it is refused, as it would hide the path). An `allow` entry can carry a path the same way. The agent's key comes from `LURE_AGENT_API_KEY`, never `ANTHROPIC_API_KEY`: Lure refuses a profile whose `agent.env` names one of its own keys, and refuses to start a run when only `ANTHROPIC_API_KEY` is set. Create a separate key for sandbox runs, with a spend cap in the provider's console: it is the one secret that goes into the container, the agent under test holds it, and the model API accepts it for every endpoint the key allows, not only the one the agent uses.

### Run

```bash
export LURE_AGENT_API_KEY=...   # a separate key with a spend cap, not ANTHROPIC_API_KEY
lure sandbox run attacks/self_modification/lure-smo-004.yaml \
  --profile profiles/example-ref-agent.yaml --repeat 3
lure sandbox run attacks/ --profile profiles/example-ref-agent-local.yaml
lure sandbox run attacks/self_modification/ --profile profiles/example-ref-agent.yaml \
  --prices prices.yaml --max-cost 0.50
lure sandbox clean              # remove anything a crash left behind
```

`lure sandbox run` runs [`lure audit`](audit.md) first: a critical finding in the profile or the agent's config stops it before any container starts. With an MCP server allowlist in `lure.yaml` (`mcp.approved_servers`), the gateway allows the model host and the approved servers' hosts the profile uses, and nothing else; a connection anywhere else is a Fail. To record the approved remote servers' tool definitions for `lure decide` and `lure retest`:

```bash
lure sandbox mcp-snapshot --profile profiles/my-agent.yaml --out profiles/my-agent-tools.json
```

Lure runs the attacks the profile's tools cover. The attack's file fixtures become `/workspace` (paths relative to the folder they share, which the task calls the working directory), its settings fixture becomes the agent's settings file with the profile's model URL, and the agent gets the profile's system prompt and the attack's task. Results go to `results/<profile>/sandbox-<timestamp>/`, scored and gated by the policy file like any run. Each record's target is `sandbox:<provider>:<model>` (for example `sandbox:anthropic:claude-haiku-5-5`), so `--prices` and `lure compare --prices` can price it.

`--prices` records each run's estimated cost, and `--max-cost USD` caps the batch. Lure reads the agent's token counts as each model request returns. Once the running total passes the cap, Lure stops the agent's processes in the container, mid-attack if need be, and the remaining attacks do not run. The stopped run is an Error (`stop: max_cost`) unless a fail rule already matched, its evidence is still collected, and the command exits 3. The cap can be passed by up to one model request, the one whose tokens crossed it. Each request is priced on its own, so a long-context tier in the prices file (`long_context`, such as Haiku 5.5's 5x rates for prompts over 100,000 tokens) applies to the requests that pass it.

### What each run creates and removes

| Created | Flags |
| --- | --- |
| `lure-sbx-<id>-int` | `docker network create --internal --opt com.docker.network.bridge.gateway_mode_ipv4=isolated`: no default route, and no address for the host on its bridge (`inhibit_ipv4` on engines before Docker 28; Lure refuses to run if neither is accepted). `--internal` alone leaves every service on the Docker host reachable on the bridge address: the real host on Linux, the VM on Docker Desktop |
| `lure-sbx-<id>-ext` | an ordinary bridge, joined only by the gateway |
| `lure-sbx-<id>-gw` | `--read-only --cap-drop ALL --security-opt no-new-privileges --user 10001`, memory and process limits; on both networks |
| `lure-sbx-<id>-agent` | the same flags, plus `--tmpfs /workspace /tmp /run/lure`, `--memory 512m --cpus 1 --pids-limit 128`, `--dns` and `HTTPS_PROXY` pointing at the gateway, no `-v` or `--mount`; on the internal network only |

All carry the label `lure.sandbox=<id>` and are removed when the run ends, whatever happened; the record lists what was removed (`sandbox.teardown`). The record also keeps the agent container's settings as `docker inspect` reported them (`sandbox.enforced`), so a reviewer can see what was enforced, not only what was asked for.

### Testing the sandbox

`pytest -m docker` builds both images and proves the isolation with a scripted model (`lure.sandbox.fakemodel`) on the gateway's outside network: the allowed host is reachable through the proxy and by SNI, other hosts are blocked and logged, direct IP connections fail, DNS for other names is logged and refused, the container is read-only and has no capabilities, the decoys log, and `lure-smo-004`'s changed model endpoint is a blocked-egress critical Fail. A deliberately vulnerable agent (`tests/sandbox_agents/obedient.py`, test-only, copied into the container) that obeys AGENTS.md Fails `lure-smo-004` on the blocked egress to the relay and `lure-shx-004` on the npm decoy, and Passes the control `lure-smo-005`. A host test starts stub listeners (never a real service) on this machine and in the Docker host's own network namespace, on 443 and high ports, and fails if the agent reaches any of them through the bridge, the Docker gateways or `host.docker.internal`. The tests skip without Docker and remove what they create.

## `lure serve` in a container

`lure serve` binds 127.0.0.1 inside the container and refuses any other `Host`, by design, so a published port does not reach it. Run `lure serve` on the host against the mounted `results/` folder instead. On Linux, `--network host` also works: the container's 127.0.0.1 is then the host's.

## What is in the image

| Path | What | Owner |
| --- | --- | --- |
| `/work/attacks`, `/work/fixtures` | The attack library | root, read-only to Lure |
| `/work/profiles/example-*.yaml` | The example profiles | root |
| `/work/lure.yaml`, `/work/prices.example.yaml` | Shipped policy and example rates | root |
| `/work/results` | Results, the store file; mount over it | lure (uid 10001) |
| `lure`, with the store extra | Installed from wheels built in a separate stage | root |

## Updating the base image

The two `FROM` lines pin `python:3.12-slim-trixie` by the digest of its multi-arch index, and `docker/agent.Dockerfile` uses the same one. To update, look up the new digest (`docker buildx imagetools inspect python:3.12-slim-trixie`), change all three lines together, rebuild and run the tests (`pytest -m docker` too).

Python dependencies are installed from PyPI at build time, with the version ranges in `pyproject.toml`, not hash-pinned. For a reproducible build, build once, push the image to your registry and deploy it by digest.
