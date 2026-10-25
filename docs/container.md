# Run Lure in a container

The [`Dockerfile`](../Dockerfile) builds an image with Lure, its attack library, fixtures, the example profiles and the shipped `lure.yaml`. It runs as a non-root user (uid 10001), its base image is pinned by digest, and it holds no secrets: API keys come in at run time and results go to a folder you mount.

The container is a convenient, tidy place to run Lure. It is not what keeps a test safe: Lure's mock tools are. See [How the sandbox works](usage.md#how-the-sandbox-works).

## Build

```bash
docker build -t lure:1.11.0 .
```

`.dockerignore` keeps `.env`, `results/`, `vetting/` and every profile except the examples out of the build context, so they can never end up in an image layer.

## Run

Rules-only work needs no network at all, so turn it off:

```bash
# Rescore or report saved runs: no model is called.
docker run --rm --network none \
  -v "$PWD/results:/work/results" \
  lure:1.11.0 report results/my-run/ --out results/my-run/report.html
```

A run against a hosted model passes the key at run time, never at build time:

```bash
docker run --rm --env-file .env \
  -v "$PWD/results:/work/results" \
  lure:1.11.0 run attacks/indirect_prompt_injection/lure-ipi-001.yaml --target anthropic
```

Your own profile, mounted read-only with its policy:

```bash
docker run --rm --env-file .env \
  -v "$PWD/profiles/my-agent.yaml:/work/profiles/my-agent.yaml:ro" \
  -v "$PWD/results:/work/results" \
  lure:1.11.0 run --profile profiles/my-agent.yaml --repeat 3 \
    --prices prices.example.yaml --max-cost 1.00
```

Copy `prices.example.yaml` to your own `prices.yaml`, check the rates, and mount it the same way.

A local model on the host, so prompts never leave the machine:

```bash
docker run --rm -e LURE_OLLAMA_URL=http://host.docker.internal:11434 \
  -v "$PWD/results:/work/results" \
  lure:1.11.0 run attacks/ --target ollama --model llama3.1:8b
```

On Linux, add `--add-host host.docker.internal:host-gateway`.

## Hardening flags

Lure needs no extra privileges, so drop them all:

```bash
docker run --rm --read-only --tmpfs /tmp \
  --cap-drop ALL --security-opt no-new-privileges \
  --env-file .env -v "$PWD/results:/work/results" \
  lure:1.11.0 run attacks/ --target anthropic --model claude-haiku-5-5
```

| Flag | Why |
| --- | --- |
| `--read-only --tmpfs /tmp` | The image's files cannot change; Lure writes only results (the mount) and temporary files |
| `--cap-drop ALL`, `--security-opt no-new-privileges` | No Linux capabilities, and no way to gain any |
| `--network none` | For report, rescore, compare, coverage, store and status: none of them calls a model |
| `--env-file .env` | Keys stay in your `.env`, out of the image and out of `docker inspect` of the image |

A container cannot limit its network to the model API by itself. If you need that, put it on a network whose only route out is an egress proxy that allows the model API's host.

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

The two `FROM` lines pin `python:3.12-slim-trixie` by the digest of its multi-arch index. To update, look up the new digest (`docker buildx imagetools inspect python:3.12-slim-trixie`), change both lines together, rebuild and run the tests.

Python dependencies are installed from PyPI at build time, with the version ranges in `pyproject.toml`, not hash-pinned. For a reproducible build, build once, push the image to your registry and deploy it by digest.
