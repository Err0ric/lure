"""Vetting: record approval decisions, and retest a profile against the last
approved run.

lure decide appends one line per decision to
vetting/<profile>/decisions.jsonl: the date, the decision, who decided (a
role), the conditions, the run folder it was based on and the profile hash
that run tested. The file is append-only: a decision is never edited or
removed, a later one supersedes it.

lure retest reruns a profile's last suite (the attacks, versions, variants,
repeat count and judge in its last run's manifest) and compares the new run
with the run the last approve or approve-with-conditions decision was based
on. Each attack (and variant) is failing when one of its runs fails the
policy. New failures are regressions; fixed attacks, unchanged ones and
attacks that no longer apply are listed too, with what changed between the
two runs: profile hash, model, judge, Lure version and attack versions.

A condition is verified when a retest can check it. Today that is removing
a tool: a condition that says to remove a tool is verified when the tool is
gone from the profile. Conditions that need a person to confirm an action
cannot be checked until Lure has a confirmation-gate mock.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from lure.profiles import Profile
from lure.rescore import MANIFEST, RETEST, record_paths

DECISIONS = ("approve", "approve-with-conditions", "reject")
APPROVED = ("approve", "approve-with-conditions")
DECISIONS_FILE = "decisions.jsonl"
DEFAULT_VETTING_DIR = "vetting"
DECISION_VERSION = 1
RETEST_FILE = RETEST
RETEST_VERSION = 1


class VettingError(ValueError):
    """A decision or retest cannot be made from these files."""


# Runs and decisions


def profile_runs(results_root: str | Path, name: str) -> list[Path]:
    """The profile's run folders (results/<name>/<timestamp>/ with a
    manifest), oldest first."""
    root = Path(results_root) / name
    if not root.is_dir():
        return []
    return sorted(p for p in root.iterdir() if (p / MANIFEST).is_file())


def read_manifest(folder: str | Path) -> dict[str, Any]:
    path = Path(folder) / MANIFEST
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise VettingError(f"{folder} is not a profile run: no {MANIFEST}") from None
    except json.JSONDecodeError as e:
        raise VettingError(f"{path}: not valid JSON: {e}") from None


def pick_run(profile: Profile, run: str | Path | None, results_root: str | Path) -> Path:
    """The run folder a decision is about: the one given, else the profile's
    latest run. It must be a run of this profile, as the file is now."""
    if run is None:
        runs = profile_runs(results_root, profile.name)
        if not runs:
            raise VettingError(f"no runs of {profile.name} under {Path(results_root) / profile.name}"
                               "; run lure run --profile first, or pass --run")
        folder = runs[-1]
    else:
        folder = Path(run)
    manifest = read_manifest(folder)
    tested = manifest.get("profile", {})
    if tested.get("name") != profile.name:
        raise VettingError(f"{folder} is a run of {tested.get('name')!r}, not {profile.name!r}")
    if tested.get("sha256") != profile.sha256:
        raise VettingError(
            f"{profile.path} changed since {folder} ran (sha256 {str(tested.get('sha256'))[:12]}, "
            f"now {profile.sha256[:12]}): rerun the profile, or pass --run with a run of the "
            "profile as it is now")
    return folder


def decision_record(profile: Profile, run: Path, decision: str, by: str,
                    conditions: list[str] | None = None, notes: str | None = None,
                    now: datetime | None = None) -> dict[str, Any]:
    """One line of the decision log. Conditions go with approve-with-conditions
    only, and it needs at least one."""
    if decision not in DECISIONS:
        raise VettingError(f"decision must be one of {', '.join(DECISIONS)}")
    if not isinstance(by, str) or not by.strip():
        raise VettingError("--by must name who decided (a role, such as \"AP operations lead\")")
    conditions = [" ".join(c.split()) for c in conditions or [] if c and c.strip()]
    if decision == "approve-with-conditions" and not conditions:
        raise VettingError("approve-with-conditions needs at least one --conditions entry")
    if decision != "approve-with-conditions" and conditions:
        raise VettingError(f"{decision} takes no conditions; use approve-with-conditions")
    manifest = read_manifest(run)
    return {
        "decision_version": DECISION_VERSION,
        "decided_at": (now or datetime.now(UTC)).isoformat(),
        "profile": profile.name,
        "profile_sha256": manifest["profile"]["sha256"],
        "decision": decision,
        "by": " ".join(by.split()),
        "conditions": conditions,
        "notes": " ".join(notes.split()) if notes else None,
        "run": str(run),
        "target": manifest.get("target"),
        "lure_version": manifest.get("lure_version"),
    }


def decisions_path(vetting_dir: str | Path, name: str) -> Path:
    return Path(vetting_dir) / name / DECISIONS_FILE


def append_decision(vetting_dir: str | Path, record: dict[str, Any]) -> tuple[Path, int]:
    """Add the record as the log's last line. Returns the file and the line
    number. Earlier lines are never rewritten."""
    path = decisions_path(vetting_dir, record["profile"])
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = read_decisions(vetting_dir, record["profile"])
    line = json.dumps(record, ensure_ascii=False) + "\n"
    with path.open("a", encoding="utf-8") as f:
        # A log someone edited by hand may lack its last newline.
        if path.stat().st_size and not path.read_bytes().endswith(b"\n"):
            f.write("\n")
        f.write(line)
    return path, len(existing) + 1


def read_decisions(vetting_dir: str | Path, name: str) -> list[dict[str, Any]]:
    path = decisions_path(vetting_dir, name)
    if not path.is_file():
        return []
    found = []
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as e:
            raise VettingError(f"{path} line {i}: not valid JSON: {e}") from None
        if not isinstance(record, dict) or record.get("decision") not in DECISIONS:
            raise VettingError(f"{path} line {i}: not a decision record")
        found.append(record)
    return found


def last_approved(decisions: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The latest approve or approve-with-conditions decision. A later reject
    does not remove it: a retest still compares with what was approved."""
    approved = [d for d in decisions if d["decision"] in APPROVED]
    return approved[-1] if approved else None


# Retest: what to rerun


def rerun_argv(manifest: dict[str, Any], profile: Profile, attack_files: dict[tuple[str, int], Path],
               results_dir: str | Path) -> list[str]:
    """lure run arguments that repeat the manifest's suite: the same attack
    versions (a pinned file when the current one is newer), variants (the
    --variants spec, or the --only-flagged screening run), replayed payload,
    max turns, adaptive attacker, repeat count and judge, under the profile
    as it is now. Manifests before version 2 have no attacker or max turns:
    those runs are repeated with the defaults."""
    keys = list(dict.fromkeys((r["attack"], r["version"]) for r in manifest.get("runs", [])))
    if not keys:
        raise VettingError("the last run's manifest lists no runs to repeat")
    missing = [f"{a} v{v}" for a, v in keys if (a, v) not in attack_files]
    if missing:
        raise VettingError(f"attack files not found for {', '.join(missing)}; a retest repeats "
                           "the same versions")
    argv = ["run", *[str(attack_files[k]) for k in keys], "--profile", str(profile.path),
            "--repeat", str(manifest.get("repeat") or 1), "--results-dir", str(results_dir)]
    for key, flag in (("only_flagged", "--only-flagged"), ("payload_from", "--payload-from")):
        if manifest.get(key):
            if not Path(manifest[key]).exists():
                raise VettingError(f"the last run used {flag} {manifest[key]}, which is gone; "
                                   "a retest repeats the same payloads")
            argv += [flag, str(manifest[key])]
    if not manifest.get("only_flagged"):
        argv += ["--variants", str(manifest.get("variants") or "none")]
    if manifest.get("attempt"):
        argv += ["--attempt", str(manifest["attempt"])]
    if manifest.get("max_turns"):
        argv += ["--max-turns", str(manifest["max_turns"])]
    attacker = manifest.get("attacker")
    if attacker:
        argv += ["--attacker-model", attacker["model"], "--attacker-target", attacker["target"],
                 "--attempts", str(attacker["attempts"])]
    judge = manifest.get("judge") or "rules"
    if judge == "rules":
        argv += ["--judge", "rules"]
    else:
        target, _, model = judge.partition(":")
        if not model:
            raise VettingError(f"cannot repeat the judge {judge!r} from the manifest")
        argv += ["--judge", "llm", "--judge-target", target, "--judge-model", model]
    return argv


# Retest: the comparison


@dataclass
class AttackStatus:
    label: str  # "lure-ipi-001 v1" or "lure-ipi-001 v1 (encoded-base64)"
    runs: int
    failing: int
    versions: tuple[int, ...]

    @property
    def fails(self) -> bool:
        return self.failing > 0


@dataclass
class Condition:
    text: str
    verified: bool
    why: str


@dataclass
class Retest:
    profile: str
    run: str
    baseline: str
    baseline_decision: dict[str, Any] | None
    new_failures: list[str] = field(default_factory=list)
    fixed: list[str] = field(default_factory=list)
    still_failing: list[str] = field(default_factory=list)
    still_passing: list[str] = field(default_factory=list)
    no_longer_run: list[tuple[str, str]] = field(default_factory=list)
    changes: list[str] = field(default_factory=list)
    conditions: list[Condition] = field(default_factory=list)
    stopped: bool = False

    @property
    def regression(self) -> bool:
        return bool(self.new_failures)

    def to_dict(self) -> dict[str, Any]:
        return {
            "retest_version": RETEST_VERSION, "profile": self.profile, "run": self.run,
            "baseline": self.baseline,
            "baseline_decision": self.baseline_decision,
            "regression": self.regression, "stopped_at_max_cost": self.stopped,
            "new_failures": self.new_failures, "fixed": self.fixed,
            "still_failing": self.still_failing, "still_passing": self.still_passing,
            "no_longer_run": [{"attack": a, "reason": r} for a, r in self.no_longer_run],
            "changes": self.changes,
            "conditions": [{"text": c.text, "verified": c.verified, "why": c.why}
                           for c in self.conditions],
        }


def statuses(folder: str | Path, policy) -> dict[tuple[str, str | None], AttackStatus]:
    """Each attack and variant in a run folder, with how many of its runs fail
    the policy. Keyed by id and variant, so a newer version of an attack
    compares with the older one."""
    pairs = []
    for path in record_paths([folder]):
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise VettingError(f"{path}: not valid JSON: {e}") from None
        pairs.append((record, str(path)))
    gate = policy.gate_saved(pairs)
    failing_where = {v.where for v in gate.violations}
    found: dict[tuple[str, str | None], AttackStatus] = {}
    for record, where in pairs:
        a = record["attack"]
        variant = (a.get("variant") or {}).get("id")
        key = (a["id"], variant)
        status = found.get(key)
        if status is None:
            status = found[key] = AttackStatus("", 0, 0, ())
        status.runs += 1
        status.failing += where in failing_where
        status.versions = tuple(sorted({*status.versions, a.get("version", 1)}))
        status.label = f"{a['id']} {_versions(status)}" + (f" ({variant})" if variant else "")
    return found


def compare(baseline: str | Path, current: str | Path, policy,
            decision: dict[str, Any] | None, profile: Profile) -> Retest:
    """The retest's findings: current run against the baseline run."""
    before, after = statuses(baseline, policy), statuses(current, policy)
    old_m, new_m = read_manifest(baseline), read_manifest(current)
    result = Retest(profile.name, str(current), str(baseline), decision,
                    stopped=bool(new_m.get("stopped_at_max_cost")))
    for key in sorted(set(before) | set(after), key=lambda k: (k[0], k[1] or "")):
        old, new = before.get(key), after.get(key)
        if new is None:
            reason = next((s["reason"] for s in new_m.get("skipped", []) if s["attack"] == key[0]),
                          "not in this retest's suite" if not result.stopped
                          else "not reached before --max-cost")
            result.no_longer_run.append((old.label, reason))
            continue
        line = f"{new.label}: failed {new.failing} of {new.runs}"
        if old is None and new.fails:
            result.new_failures.append(line + " (not in the approved run)")
        elif old is None:
            result.still_passing.append(new.label)
        elif new.fails and not old.fails:
            result.new_failures.append(line + f", was 0 of {old.runs}")
        elif old.fails and not new.fails:
            result.fixed.append(f"{new.label}: failed 0 of {new.runs}, was {old.failing} of "
                                f"{old.runs}")
        elif new.fails:
            result.still_failing.append(line + f", was {old.failing} of {old.runs}")
        else:
            result.still_passing.append(new.label)
    result.changes = changes(old_m, new_m, before, after)
    result.conditions = verify_conditions((decision or {}).get("conditions") or [], old_m, new_m)
    return result


def changes(old: dict[str, Any], new: dict[str, Any],
            before: dict[tuple[str, str | None], AttackStatus],
            after: dict[tuple[str, str | None], AttackStatus]) -> list[str]:
    """What differs between the two runs, one line each."""
    found = []
    o, n = old.get("profile", {}), new.get("profile", {})
    if o.get("sha256") != n.get("sha256"):
        found.append(f"profile sha256 {str(o.get('sha256'))[:12]} -> {str(n.get('sha256'))[:12]}")
        old_tools = {t["name"]: t["maps_to"] for t in o.get("tools", [])}
        new_tools = {t["name"]: t["maps_to"] for t in n.get("tools", [])}
        for name in sorted(set(old_tools) - set(new_tools)):
            found.append(f"tool removed: {name} ({old_tools[name]})")
        for name in sorted(set(new_tools) - set(old_tools)):
            found.append(f"tool added: {name} ({new_tools[name]})")
    for key, label in (("target", "model"), ("judge", "judge"), ("lure_version", "Lure")):
        if old.get(key) != new.get(key):
            found.append(f"{label} {old.get(key)} -> {new.get(key)}")
    for key in sorted(set(before) & set(after), key=lambda k: (k[0], k[1] or "")):
        if before[key].versions != after[key].versions:
            found.append(f"attack version {key[0]} {_versions(before[key])} -> "
                         f"{_versions(after[key])}")
    if old.get("policy", {}).get("sha256") != new.get("policy", {}).get("sha256"):
        found.append(f"policy {old.get('policy', {}).get('source')} changed")
    for key, label in (("attacker", "adaptive attacker"), ("max_turns", "max turns")):
        if key in old and old.get(key) != new.get(key):
            found.append(f"{label} {_setting(old.get(key))} -> {_setting(new.get(key))}")
    for attack, variant in sorted(_payloads(old) - _payloads(new), key=str):
        found.append(f"payload not repeated: {attack} {variant or 'own payload'}")
    for attack, variant in sorted(_payloads(new) - _payloads(old), key=str):
        found.append(f"payload not in the approved run: {attack} {variant or 'own payload'}")
    return found


def _payloads(manifest: dict[str, Any]) -> set[tuple[str, str | None]]:
    """Each attack and variant the manifest's runs planted."""
    return {(r["attack"], r.get("variant")) for r in manifest.get("runs", [])}


def _setting(value: Any) -> str:
    if isinstance(value, dict):
        return f"{value.get('target')}:{value.get('model')} x{value.get('attempts')}"
    return "none" if value is None else str(value)


def _versions(status: AttackStatus) -> str:
    return "/".join(f"v{v}" for v in status.versions)


def verify_conditions(conditions: list[str], old: dict[str, Any],
                      new: dict[str, Any]) -> list[Condition]:
    """Which of the approved conditions this retest verified. A condition
    that says to remove a tool is verified once the tool is gone from the
    profile; the others need a confirmation-gate mock Lure does not have yet."""
    old_names = [t["name"] for t in old.get("profile", {}).get("tools", [])]
    new_names = {t["name"] for t in new.get("profile", {}).get("tools", [])}
    found = []
    for text in conditions:
        named = [t for t in old_names if re.search(
            rf"\bremov\w*\s+(?:the\s+)?`?{re.escape(t)}`?(?![\w-])", text, re.IGNORECASE)]
        gone = [t for t in named if t not in new_names]
        if named and gone == named:
            found.append(Condition(text, True, f"{', '.join(gone)} is no longer in the profile"))
        elif named:
            kept = [t for t in named if t in new_names]
            found.append(Condition(text, False, f"{', '.join(kept)} is still in the profile"))
        else:
            found.append(Condition(text, False, "a retest can only verify a removed tool so far"))
    return found


def write_retest(result: Retest, folder: str | Path) -> Path:
    path = Path(folder) / RETEST_FILE
    path.write_text(json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8")
    return path
