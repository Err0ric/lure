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
    sbx.add_parser("clean", help="remove leftover sandbox containers and networks")


def sandbox_main(args: argparse.Namespace, out: TextIO = sys.stdout) -> int:
    try:
        if args.sandbox_command == "build":
            return _build(args, out)
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


def _run(args, out: TextIO) -> int:
    from lure.batch import collect_attack_paths
    from lure.cli import _policy, exit_code, print_policy, print_result
    from lure.policy import PolicyRun
    from lure.sandbox.run import key_problem, missing_env, run_in_sandbox

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
    problem = key_problem(profile)
    if problem:
        raise ProfileError(problem)
    unset = missing_env(profile)
    if unset:
        raise ProfileError(f"agent.env names variables that are not set: {', '.join(unset)}")
    policy = _policy(args)
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
    results_dir = args.results_dir or str(
        Path("results") / profile.name / f"sandbox-{datetime.now(UTC):%Y%m%dT%H%M%SZ}")
    print(f"Sandbox:   {profile.name}: {agent_image}, egress allowed to "
          f"{', '.join((profile.agent.model_allow, *profile.agent.allow))} only", file=out)
    results = []
    for attack in attacks:
        for _ in range(args.repeat):
            prepared, prompt, canary = prepare_for_profile(profile, attack)
            result = run_in_sandbox(prepared, profile, prompt, gateway_image=args.gateway_image,
                                    agent_image=agent_image, org_policy=policy.exposure,
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
    gate = policy.gate([PolicyRun.from_result(r) for r in results])
    print(file=out)
    print_policy(gate, out)
    return exit_code(gate, [r.judgment.verdict for r in results], False)
