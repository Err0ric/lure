"""Run one agent in a throwaway container, through the docker CLI.

Per run, Lure creates and afterwards removes:

  lure-sbx-<id>-int    an --internal network: no default route, nothing on
                       it can reach the host or the internet directly
  lure-sbx-<id>-ext    an ordinary bridge network, joined only by the gateway
  lure-sbx-<id>-gw     the gateway (lure.sandbox.gateway), on both networks
  lure-sbx-<id>-agent  the agent, on the internal network only

The agent container runs as a non-root user, with a read-only root
filesystem, tmpfs /workspace, /tmp and /run/lure, no host mounts, every
Linux capability dropped, no-new-privileges, and memory, CPU and process
limits. Its proxy settings and DNS point at the gateway. The workspace is
copied in as a tar over `docker exec` and read back the same way, so no
host path is ever mounted. Everything carries the label lure.sandbox=<id>;
`lure sandbox clean` removes anything a crash left behind.

The only things passed into the agent's environment are the proxy
settings and the variable names the profile lists (for example a capped
test model key), inherited from Lure's environment by name, so their
values never appear on a command line.
"""

from __future__ import annotations

import io
import json
import os
import random
import secrets
import shutil
import subprocess
import tarfile
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Self

from lure.sandbox.evidence import json_lines

DOCKER = "docker"
LABEL = "lure.sandbox"
UID = 10001
WORKSPACE = "/workspace"
DECOY_LOG = "/run/lure/decoys.jsonl"
SUBNET = "10.213.{}.0/24"
GATEWAY_HOST = 2
READY_TIMEOUT = 30.0
AGENT_TIMEOUT = 900
PROXY_PORT = 3128


class SandboxError(RuntimeError):
    """Docker is missing, a step failed, or the gateway never came up."""


@dataclass(frozen=True)
class Limits:
    memory: str = "512m"
    cpus: str = "1.0"
    pids: int = 128
    workspace: str = "64m"


@dataclass(frozen=True)
class Outside:
    """A container on the outside network only, reachable through the
    gateway under `alias` (the integration tests' fake model)."""

    alias: str
    image: str
    command: tuple[str, ...]


@dataclass(frozen=True)
class SandboxSpec:
    agent_image: str
    gateway_image: str
    allow: tuple[str, ...]
    # Names of environment variables the agent inherits from Lure's.
    env: tuple[str, ...] = ()
    limits: Limits = field(default_factory=Limits)
    outside: tuple[Outside, ...] = ()


Runner = Callable[..., subprocess.CompletedProcess]


def run_docker(args: Sequence[str], input: bytes | None = None, timeout: float = 120,
               check: bool = True) -> subprocess.CompletedProcess:
    try:
        done = subprocess.run([DOCKER, *args], input=input, capture_output=True,
                              timeout=timeout, check=False)
    except FileNotFoundError as e:
        raise SandboxError("docker is not installed or not on PATH") from e
    except subprocess.TimeoutExpired as e:
        raise SandboxError(f"docker {args[0]} timed out after {timeout:.0f}s") from e
    if check and done.returncode != 0:
        raise SandboxError(f"docker {' '.join(args[:2])} failed: "
                           f"{done.stderr.decode(errors='replace').strip()}")
    return done


def docker_available() -> bool:
    """True when the docker CLI is installed and its daemon answers."""
    if shutil.which(DOCKER) is None:
        return False
    try:
        return run_docker(["info", "--format", "{{.ServerVersion}}"], timeout=20,
                          check=False).returncode == 0
    except SandboxError:
        return False


def hardening(limits: Limits) -> list[str]:
    """The docker run flags every sandbox container gets."""
    return ["--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--user", f"{UID}:{UID}", "--memory", limits.memory, "--memory-swap", limits.memory,
            "--cpus", limits.cpus, "--pids-limit", str(limits.pids)]


class Sandbox:
    """One run's networks and containers. Use as a context manager: the
    exit always tears everything down, whatever happened."""

    def __init__(self, spec: SandboxSpec, runner: Runner = run_docker,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self.spec = spec
        self.run = runner
        self.sleep = sleep
        self.id = secrets.token_hex(4)
        base = f"lure-sbx-{self.id}"
        self.internal, self.external = f"{base}-int", f"{base}-ext"
        self.gateway, self.agent = f"{base}-gw", f"{base}-agent"
        self.outside_names: list[str] = []
        self.gateway_ip: str | None = None
        self.subnet: str | None = None
        self.created: list[tuple[str, str]] = []
        self.removed: list[str] = []
        self.leftover: list[str] = []

    def __enter__(self) -> Self:
        try:
            self.up()
        except BaseException:
            self.down()
            raise
        return self

    def __exit__(self, *exc) -> None:
        self.down()

    def _label(self) -> list[str]:
        return ["--label", f"{LABEL}={self.id}"]

    def up(self) -> None:
        self._internal_network()
        self.run(["network", "create", *self._label(), self.external])
        self.created.append(("network", self.external))
        for n, svc in enumerate(self.spec.outside):
            name = f"lure-sbx-{self.id}-out{n}"
            self.run(["run", "-d", "--name", name, *self._label(), "--network", self.external,
                      "--network-alias", svc.alias, *hardening(Limits(memory="128m", pids=64)),
                      "--entrypoint", svc.command[0], svc.image, *svc.command[1:]])
            self.created.append(("container", name))
            self.outside_names.append(name)
        self.run(self.gateway_args())
        self.created.append(("container", self.gateway))
        self.run(["network", "connect", self.external, self.gateway])
        self._wait_ready()
        self.run(self.agent_args())
        self.created.append(("container", self.agent))

    def _internal_network(self) -> None:
        last = ""
        for n in random.sample(range(1, 255), 12):
            subnet = SUBNET.format(n)
            done = self.run(["network", "create", "--internal", "--subnet", subnet,
                             *self._label(), self.internal], check=False)
            if done.returncode == 0:
                self.subnet = subnet
                self.gateway_ip = subnet.rsplit(".", 1)[0] + f".{GATEWAY_HOST}"
                self.created.append(("network", self.internal))
                return
            last = done.stderr.decode(errors="replace").strip()
            if "overlap" not in last.lower():
                break
        raise SandboxError(f"could not create the internal network: {last}")

    def gateway_args(self) -> list[str]:
        allow = [a for host in self.spec.allow for a in ("--allow", host)]
        return ["run", "-d", "--name", self.gateway, *self._label(),
                "--network", self.internal, "--ip", self.gateway_ip,
                *hardening(Limits(memory="256m", pids=64)), "--tmpfs", "/tmp:size=8m",
                "--entrypoint", "python", self.spec.gateway_image,
                "-m", "lure.sandbox.gateway", "--address", self.gateway_ip, *allow]

    def agent_args(self) -> list[str]:
        proxy = f"http://{self.gateway_ip}:{PROXY_PORT}"
        env = []
        for name in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"):
            env += ["-e", f"{name}={proxy}"]
        env += ["-e", "NO_PROXY=", "-e", "no_proxy="]
        for name in self.spec.env:
            env += ["-e", name]
        limits = self.spec.limits
        return ["run", "-d", "--init", "--name", self.agent, *self._label(),
                "--network", self.internal, "--dns", self.gateway_ip, "--hostname", "sandbox",
                *hardening(limits),
                "--tmpfs", (f"{WORKSPACE}:rw,nosuid,nodev,size={limits.workspace},"
                            f"uid={UID},gid={UID},mode=0755"),
                "--tmpfs", "/tmp:rw,nosuid,nodev,size=16m",
                "--tmpfs", f"/run/lure:rw,nosuid,nodev,noexec,size=4m,uid={UID},gid={UID}",
                *env, "--workdir", WORKSPACE,
                "--entrypoint", "/bin/sleep", self.spec.agent_image, "infinity"]

    def _wait_ready(self) -> None:
        deadline = time.monotonic() + READY_TIMEOUT
        while time.monotonic() < deadline:
            if any(e.get("event") == "ready" for e in self.gateway_events()):
                return
            self.sleep(0.2)
        logs = self.run(["logs", self.gateway], check=False)
        raise SandboxError("the gateway did not start: "
                           + (logs.stdout + logs.stderr).decode(errors="replace")[-500:])

    def exec(self, command: Sequence[str], input: bytes | None = None,
             timeout: float = AGENT_TIMEOUT, container: str | None = None,
             check: bool = False) -> subprocess.CompletedProcess:
        """Run a command in the agent's container (or another one)."""
        flags = ["-i"] if input is not None else []
        return self.run(["exec", *flags, container or self.agent, *command], input=input,
                        timeout=timeout, check=check)

    def seed(self, files: dict[str, bytes]) -> None:
        """Copy files into /workspace, as the agent's user."""
        self.exec(["tar", "-x", "-C", WORKSPACE, "-f", "-"], input=make_tar(files), check=True)

    def snapshot(self) -> dict[str, bytes]:
        """Every regular file under /workspace, by relative path."""
        done = self.exec(["tar", "-c", "-C", WORKSPACE, "-f", "-", "."], check=True)
        return read_tar(done.stdout)

    def decoys(self) -> list[dict[str, Any]]:
        done = self.exec(["cat", DECOY_LOG])
        return json_lines(done.stdout.decode(errors="replace")) if done.returncode == 0 else []

    def gateway_events(self) -> list[dict[str, Any]]:
        done = self.run(["logs", self.gateway], check=False)
        return json_lines(done.stdout.decode(errors="replace"))

    def outside_logs(self, n: int = 0) -> list[dict[str, Any]]:
        done = self.run(["logs", self.outside_names[n]], check=False)
        return json_lines(done.stdout.decode(errors="replace"))

    def enforced(self) -> dict[str, Any]:
        """The agent container's settings as Docker reports them, for the
        record: what was enforced, not only what Lure asked for."""
        done = self.run(["inspect", self.agent], check=False)
        try:
            info = json.loads(done.stdout)[0]
        except (ValueError, IndexError):
            return {}
        host = info.get("HostConfig", {})
        return {
            "user": info.get("Config", {}).get("User"),
            "read_only_root": host.get("ReadonlyRootfs"),
            "cap_drop": host.get("CapDrop"),
            "cap_add": host.get("CapAdd"),
            "privileged": host.get("Privileged"),
            "security_opt": host.get("SecurityOpt"),
            "memory": host.get("Memory"),
            "nano_cpus": host.get("NanoCpus"),
            "pids_limit": host.get("PidsLimit"),
            "tmpfs": sorted(host.get("Tmpfs") or {}),
            "host_mounts": [m.get("Source") for m in info.get("Mounts", [])
                            if m.get("Type") == "bind"],
            "networks": sorted(info.get("NetworkSettings", {}).get("Networks", {})),
        }

    def down(self) -> None:
        """Remove every container and network this run created. Never
        raises; what could not be removed is listed in leftover."""
        for kind, name in reversed(self.created):
            args = ["rm", "-f", name] if kind == "container" else ["network", "rm", name]
            try:
                done = self.run(args, check=False, timeout=60)
                ok = done.returncode == 0
            except SandboxError:
                ok = False
            (self.removed if ok else self.leftover).append(name)
        self.created = []

    def teardown_record(self) -> dict[str, Any]:
        return {"removed": list(self.removed), "leftover": list(self.leftover)}


def make_tar(files: dict[str, bytes]) -> bytes:
    """A tar of the files, owned by the agent's user."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        dirs = sorted({"/".join(p.split("/")[:i]) for p in files
                       for i in range(1, p.count("/") + 1)})
        for d in dirs:
            info = tarfile.TarInfo(d)
            info.type, info.mode, info.uid, info.gid = tarfile.DIRTYPE, 0o755, UID, UID
            tar.addfile(info)
        for path, data in sorted(files.items()):
            info = tarfile.TarInfo(path)
            info.size, info.mode, info.uid, info.gid = len(data), 0o644, UID, UID
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def read_tar(data: bytes) -> dict[str, bytes]:
    """Regular files in a tar, by path without a leading './'. Links and
    devices are listed by name with a marker, never followed."""
    found: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tar:
        for member in tar:
            path = member.name.removeprefix("./")
            if not path or member.isdir():
                continue
            if member.isfile():
                f = tar.extractfile(member)
                found[path] = f.read() if f is not None else b""
            else:
                found[path] = f"[not a regular file: {member.type!r} -> {member.linkname}]".encode()
    return found


def labelled() -> dict[str, list[str]]:
    """Leftover containers and networks carrying the sandbox label."""
    containers = run_docker(["ps", "-a", "-q", "--filter", f"label={LABEL}"], check=False)
    networks = run_docker(["network", "ls", "-q", "--filter", f"label={LABEL}"], check=False)
    return {"containers": containers.stdout.decode().split(),
            "networks": networks.stdout.decode().split()}


def clean() -> dict[str, list[str]]:
    """Remove every leftover sandbox container and network."""
    found = labelled()
    if found["containers"]:
        run_docker(["rm", "-f", *found["containers"]], check=False)
    if found["networks"]:
        run_docker(["network", "rm", *found["networks"]], check=False)
    return found


def environment_has(names: Sequence[str]) -> list[str]:
    """The names that are not set in Lure's environment."""
    return [n for n in names if not os.environ.get(n)]
