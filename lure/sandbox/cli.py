"""lure sandbox: build the sandbox images, run real agents in it, clean up.

  lure sandbox build                 build lure:<version> (the gateway) and
                                     lure-ref-agent:<version> from this repo
  lure sandbox run ATTACK --profile P
                                     run attacks against the profile's agent,
                                     each in a fresh container
  lure sandbox clean                 remove containers and networks a crash
                                     left behind (label lure.sandbox)

The profile needs an agent: block and isolation: container. A profile
with isolation: vm describes a VM you run yourself: Lure refuses to run it
in a container, and never runs an agent without isolation.
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO

from lure import __version__
from lure.attacks import AttackError, load_attack
from lure.exposure import PolicyError
from lure.profiles import ProfileError, load_profile
from lure.profiles import prepare as prepare_for_profile
from lure.profiles import select as select_for_profile
from lure.sandbox.docker import SandboxError, clean, docker_available, run_docker

GATEWAY_IMAGE = f"lure:{__version__}"
AGENT_IMAGE = f"lure-ref-agent:{__version__}"
AGENT_DOCKERFILE = "docker/agent.Dockerfile"
EXIT_OK, EXIT_POLICY, EXIT_BAD_INPUT = 0, 1, 2


def add_parser(sub) -> None:
    sandbox = sub.add_parser("sandbox", help="run a real agent in a throwaway container behind "
                                             "Lure's egress gateway (docs/container.md)")
    sbx = sandbox.add_subparsers(dest="sandbox_command", required=True)
    build = sbx.add_parser("build", help="build the gateway and reference agent images from "
                                         "this repository")
    build.add_argument("--tag", default=__version__, help=f"image tag (default {__version__})")
    run = sbx.add_parser("run", help="run attacks against a profile's agent in the sandbox")
    run.add_argument("attack", nargs="+", help="attack YAML files or folders")
    run.add_argument("--profile", required=True,
                     help="a profile with an agent: block and isolation: container")
    run.add_argument("--gateway-image", default=GATEWAY_IMAGE,
                     help=f"the gateway image (default {GATEWAY_IMAGE})")
    run.add_argument("--agent-image", help="override the profile's agent.image")
    run.add_argument("--repeat", type=int, default=1, help="runs per attack (default 1)")
    run.add_argument("--results-dir", help="where to save results (default "
                                           "results/<profile>/sandbox-<timestamp>)")
    run.add_argument("--policy", "--org-policy", dest="policy",
                     help="policy file (default lure.yaml if present)")
    run.add_argument("--no-policy", dest="no_policy", action="store_true")
    run.add_argument("--prices", help="prices file (USD per million tokens) to estimate spend")
    run.add_argument("--max-cost", type=float, metavar="USD",
                     help="stop when the estimated spend passes this, mid-attack if need be "
                          "(needs --prices)")
    sbx.add_parser("clean", help="remove leftover sandbox containers and networks")
    snap = sbx.add_parser("mcp-snapshot", help="fetch the approved remote MCP servers' tool "
                                               "definitions from inside the sandbox")
    snap.add_argument("--profile", required=True, help="the profile whose mcp_servers to fetch")
    snap.add_argument("--out", required=True, help="where to write the snapshot JSON")
    snap.add_argument("--gateway-image", default=GATEWAY_IMAGE)
    snap.add_argument("--agent-image", default=AGENT_IMAGE)
    snap.add_argument("--policy", "--org-policy", dest="policy",
                      help="policy file with the mcp: allowlist (default lure.yaml)")
    snap.add_argument("--no-policy", dest="no_policy", action="store_true")


def sandbox_main(args: argparse.Namespace, out: TextIO = sys.stdout) -> int:
    try:
        if args.sandbox_command == "build":
            return _build(args, out)
        if args.sandbox_command == "mcp-snapshot":
            return _snapshot(args, out)
        if args.sandbox_command == "clean":
            found = clean()
            print(f"Removed {len(found['containers'])} containers and "
                  f"{len(found['networks'])} networks.", file=out)
            return EXIT_OK
        return _run(args, out)
    except (SandboxError, ProfileError, AttackError, PolicyError, ValueError) as e:
        print(f"lure: {e}", file=sys.stderr)
        return EXIT_BAD_INPUT


def _build(args, out: TextIO) -> int:
    if not Path("Dockerfile").is_file() or not Path(AGENT_DOCKERFILE).is_file():
        raise SandboxError("run lure sandbox build from the root of a Lure checkout")
    for name, extra in ((f"lure:{args.tag}", []),
                        (f"lure-ref-agent:{args.tag}", ["-f", AGENT_DOCKERFILE])):
        print(f"Building {name} ...", file=out)
        run_docker(["build", "-q", *extra, "-t", name, "."], timeout=1800)
    print("Done.", file=out)
    return EXIT_OK


def _snapshot(args, out: TextIO) -> int:
    import json

    from lure.audit.mcp import tool_hashes
    from lure.cli import _policy
    from lure.sandbox.snapshot import fetch_snapshot

    profile = load_profile(args.profile)
    policy = _policy(args)
    if policy.mcp is None:
        raise PolicyError("the policy has no mcp: approved_servers; nothing is approved to fetch")
    servers, skipped = [], []
    for name in profile.mcp_servers:
        approved = policy.mcp.get(name)
        if approved is None:
            raise PolicyError(f"{name} is not on the approved list; Lure fetches approved "
                              "servers only")
        if approved.url is None:
            skipped.append(name)
        else:
            servers.append((name, approved.url))
    for name in skipped:
        print(f"Skipped:   {name}: a local server; Lure never starts one, export its snapshot",
              file=out)
    if not servers:
        raise ProfileError("no approved remote MCP server in the profile's mcp_servers")
    if not docker_available():
        raise SandboxError("docker is not available: install it and start the daemon")
    allow = tuple(dict.fromkeys(policy.mcp.get(n).host for n, _ in servers))
    data, egress = fetch_snapshot(servers, args.agent_image, args.gateway_image, allow)
    path = Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    hashes = tool_hashes(path)
    for name, _ in servers:
        entry = data.get(name, {})
        if "error" in entry:
            print(f"Failed:    {name}: {entry['error']}", file=out)
        else:
            print(f"Fetched:   {name}: {len(entry.get('tools', []))} tools, definitions "
                  f"{hashes.get(name, '')[:12]}", file=out)
    blocked = [e for e in egress if not e.get("allowed")]
    print(f"Wrote {path}; egress allowed to {', '.join(allow)} only"
          + (f", {len(blocked)} blocked" if blocked else ""), file=out)
    return EXIT_OK if all("error" not in data.get(n, {}) for n, _ in servers) else EXIT_POLICY


def _run(args, out: TextIO) -> int:
    from lure.batch import collect_attack_paths
    from lure.cli import _policy, exit_code, print_policy, print_result
    from lure.policy import PolicyRun
    from lure.sandbox.run import key_problem, missing_env, run_in_sandbox, spec_for

    profile = load_profile(args.profile)
    if profile.agent is None:
        raise ProfileError(f"{profile.path.name}: no agent: block; lure sandbox run runs a "
                           "real agent (use lure run --profile for the mock-tool test)")
    if profile.isolation != "container":
        raise ProfileError(f"{profile.path.name}: isolation is {profile.isolation}; Lure runs "
                           "agents only in its container sandbox. Run a vm profile in your own "
                           "isolated VM")
    if args.repeat < 1:
        raise ValueError("--repeat must be at least 1")
    budget = _budget(args, profile)
    problem = key_problem(profile)
    if problem:
        raise ProfileError(problem)
    unset = missing_env(profile)
    if unset:
        raise ProfileError(f"agent.env names variables that are not set: {', '.join(unset)}")
    policy = _policy(args)
    from lure.audit.cli import preflight
    results_dir = args.results_dir or str(
        Path("results") / profile.name / f"sandbox-{datetime.now(UTC):%Y%m%dT%H%M%SZ}")
    # Before any container or model call: a critical finding stops here.
    if preflight(profile, policy, results_dir, out).blocked:
        return EXIT_POLICY
    attacks = [load_attack(p) for t in args.attack for p in collect_attack_paths(t)]
    attacks, skipped = select_for_profile(profile, attacks)
    for s in skipped:
        print(f"Skipped:   {s.attack.id}: {s.reason}", file=out)
    if not attacks:
        raise AttackError("the profile's tools cover none of these attacks")
    if not docker_available():
        raise SandboxError("docker is not available: install it and start the daemon")
    agent_image = args.agent_image or profile.agent.image
    for image in (args.gateway_image, agent_image):
        if run_docker(["image", "inspect", image], check=False).returncode != 0:
            raise SandboxError(f"image {image} not found; run lure sandbox build (Lure pulls "
                               "nothing)")
    print(f"Sandbox:   {profile.name}: {agent_image}, egress allowed to "
          f"{', '.join(spec_for(profile, agent_image, args.gateway_image, policy.mcp).allow)} "
          "only", file=out)
    results = []
    for attack in attacks:
        for _ in range(args.repeat):
            if budget is not None and budget.stopped:
                break
            prepared, prompt, canary = prepare_for_profile(profile, attack)
            result = run_in_sandbox(prepared, profile, prompt, gateway_image=args.gateway_image,
                                    agent_image=agent_image, org_policy=policy.exposure,
                                    mcp=policy.mcp, budget=budget,
                                    profile_record=profile.record(canary))
            result.save(results_dir)
            results.append(result)
            print_result(result, out)
            blocked = result.exposure.get("egress_blocked") or []
            print(f"Egress:    {len(blocked)} blocked, "
                  f"{len(result.exposure.get('dns_lookups') or [])} DNS lookups, "
                  f"{len(result.sandbox['decoys'])} decoy calls; saved {result.saved_to}",
                  file=out)
            if result.sandbox["teardown"]["leftover"]:
                print("Warning:   not removed: "
                      + ", ".join(result.sandbox["teardown"]["leftover"])
                      + " (lure sandbox clean)", file=out)
    stopped = budget is not None and budget.stopped
    if budget is not None:
        print(file=out)
        if stopped:
            print(f"Stopped:   max cost ${budget.max_cost:.2f} reached; spent "
                  f"${budget.total:.4f}; {len(results)} runs done", file=out)
        else:
            print(f"Spend:     ${budget.total:.4f} (target), estimated from recorded tokens at "
                  f"the rates in {budget.prices.source}", file=out)
    gate = policy.gate([PolicyRun.from_result(r) for r in results])
    print(file=out)
    print_policy(gate, out)
    return exit_code(gate, [r.judgment.verdict for r in results], stopped)


def _budget(args, profile):
    """The spend tracker for --prices and --max-cost, checked before any run."""
    from lure.budget import Budget
    from lure.prices import PricesError, load_prices
    from lure.sandbox.run import target_model
    if args.max_cost is not None and args.max_cost <= 0:
        raise ValueError("--max-cost must be above 0")
    if args.max_cost is not None and not args.prices:
        raise PricesError("--max-cost needs --prices")
    if not args.prices:
        return None
    budget = Budget(load_prices(args.prices), args.max_cost)
    budget.check_models([target_model(profile)])
    return budget
