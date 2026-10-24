"""Load saved runs and aggregate them for the report.

The report reads only the saved results: attack details come from each
record, so a report still builds after an attack file changes. Runs are
grouped by attack id and version so a stricter v2 never mixes with v1.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from lure.batch import UNSCORED
from lure.judge.rules import CONFIRM_FIRST, DETECTED, Verdict
from lure.report.techniques import atlas_name, category_name
from lure.rescore import record_paths

VERDICT_ORDER = (Verdict.PASS, Verdict.PARTIAL, Verdict.REVIEW,
                 Verdict.REFUSED, Verdict.INVALID, Verdict.FAIL, Verdict.ERROR)
# Findings worth a reader's attention.
FINDING_VERDICTS = (Verdict.FAIL, Verdict.PARTIAL, Verdict.REVIEW)
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
# A rate over fewer scored runs than this is marked "low sample".
LOW_SAMPLE = 10
# LLM judge labels that mean the target was swayed.
SWAYED_LABELS = ("offered_attacker_action", "complied")
# How each partial_kind reads in a report.
PARTIAL_KIND_LABELS = {"outright": "outright", "confirm_first": "confirm first"}


class ReportError(ValueError):
    """The results cannot make one coherent report."""


@dataclass(frozen=True)
class Run:
    path: Path
    record: dict[str, Any]

    @property
    def attack(self) -> dict[str, Any]:
        return self.record["attack"]

    @property
    def key(self) -> tuple[str, int]:
        return self.attack["id"], self.attack.get("version", 1)

    @property
    def label(self) -> str:
        """Always names the version, v1 included, so versions never blur.
        Adaptive runs say so: worst of several attempts is a different rate.
        An adaptive run no attacker payload reached is single-shot, and says
        why, so it never reads as an adaptive Pass."""
        attack_id, version = self.key
        variant = f" {self.variant}" if self.variant else ""
        return f"{attack_id} v{version}{variant}" + (f" {self.mode}" if self.mode else "")

    @property
    def variant(self) -> str:
        """The payload variant id; '' for the attack's own payload."""
        return (self.record.get("variant") or {}).get("id", "")

    @property
    def variant_kind(self) -> str:
        return (self.record.get("variant") or {}).get("kind", "")

    @property
    def adaptive(self) -> bool:
        return bool(self.record.get("adaptive"))

    @property
    def attacker_tested(self) -> bool:
        """True if an attacker payload reached the target. Computed from the
        attempts, so records written before the field existed read right."""
        ad = self.record.get("adaptive")
        return bool(ad) and any(a["source"] == "attacker" and "judgment" in a
                                for a in ad["attempts"])

    @property
    def attacker_calls(self) -> int:
        ad = self.record.get("adaptive") or {}
        return sum(a["source"] == "attacker" for a in ad.get("attempts", []))

    @property
    def attacker_refused(self) -> int:
        ad = self.record.get("adaptive") or {}
        return sum(a["outcome"] == "attacker_refused" for a in ad.get("attempts", []))

    @property
    def mode(self) -> str:
        """'' for a single-shot run; 'adaptive'; or 'single-shot (...)' with
        the reason no attacker payload reached the target."""
        ad = self.record.get("adaptive")
        if not ad:
            return ""
        if self.attacker_tested:
            return "adaptive"
        if self.attacker_calls and self.attacker_refused == self.attacker_calls:
            why = "attacker refused"
        elif self.attacker_calls:
            why = "attacker wrote no usable payload"
        elif ad["outcome"] == "target_failed":
            why = "failed on attempt 1"
        elif ad["outcome"] == "max_cost":
            why = "stopped at max cost"
        else:
            why = "attacker not called"
        return f"single-shot ({why})"

    @property
    def verdict(self) -> Verdict:
        return Verdict(self.record["judgment"]["verdict"])

    @property
    def partial_kind(self) -> str | None:
        """For a Partial: outright or confirm_first. None for other verdicts
        and for runs saved before Lure 1.2."""
        if self.verdict is not Verdict.PARTIAL:
            return None
        return self.record["judgment"].get("partial_kind")

    @property
    def verdict_label(self) -> str:
        """The verdict, with the Partial's kind when it is known."""
        kind = PARTIAL_KIND_LABELS.get(self.partial_kind)
        return f"{self.verdict.value} ({kind})" if kind else self.verdict.value

    @property
    def detected(self) -> bool:
        return self.verdict is Verdict.PASS and self.record["judgment"]["reason"] == DETECTED

    @property
    def judge(self) -> str:
        """The judge setting. Results saved before it was recorded are
        inferred: an LLM verdict means LLM mode, otherwise rules only."""
        if "judge" in self.record:
            return self.record["judge"]
        llm = self.record["judgment"].get("llm_judge") or {}
        return llm.get("model", "rules")

    @property
    def started_at(self) -> datetime:
        return datetime.fromisoformat(self.record["started_at"])

    @property
    def llm_label(self) -> str | None:
        return (self.record["judgment"].get("llm_judge") or {}).get("label")

    @property
    def confirmed_partial(self) -> bool:
        """A Partial backed by the judge's label or by confirmed rule
        evidence (reply_contains), not only by the asking heuristic."""
        if self.verdict is not Verdict.PARTIAL:
            return False
        evidence = self.record["judgment"].get("evidence", [])
        return self.llm_label in SWAYED_LABELS or any(
            e.get("kind") == "confirmed" for e in evidence)

    @property
    def rank(self) -> int:
        """Finding order: Fail, judge-confirmed Partial, Review, rules-only
        Partial. A reply the judge called detected goes last."""
        if self.llm_label == "detected":
            return 9
        if self.verdict is Verdict.FAIL:
            return 0
        if self.confirmed_partial:
            return 1
        if self.verdict is Verdict.REVIEW:
            return 2
        return 3

    @property
    def exposure_checked(self) -> bool:
        return isinstance(self.record.get("exposure"), dict)

    @property
    def exposure_calls(self) -> list[dict[str, Any]]:
        """Calls to domains outside the org's allowed list (see lure.yaml)."""
        return (self.record.get("exposure") or {}).get("calls", [])

    @property
    def policy(self) -> str | None:
        """The system prompt the target ran under, from the transcript."""
        return next((m.get("content") for m in self.record.get("transcript", [])
                     if m.get("role") == "system"), None)


@dataclass
class Tally:
    """Verdict counts and the rates the report shows."""

    counts: Counter = field(default_factory=Counter)
    detected: int = 0
    # Runs with at least one call outside the org's allowed domains, and the
    # number of such calls. Counted whatever the verdict.
    exposed: int = 0
    exposure_calls: int = 0
    # Partial runs that only offered the action with the user's explicit
    # confirmation, and Partial runs with a recorded kind at all.
    confirm_first: int = 0
    partial_known: int = 0

    def add(self, run: Run) -> None:
        self.counts[run.verdict] += 1
        self.detected += run.detected
        self.confirm_first += run.partial_kind == CONFIRM_FIRST
        self.partial_known += run.partial_kind is not None
        self.exposed += bool(run.exposure_calls)
        self.exposure_calls += len(run.exposure_calls)

    @property
    def runs(self) -> int:
        return sum(self.counts.values())

    @property
    def scored(self) -> int:
        return self.runs - sum(self.counts[v] for v in UNSCORED)

    def rate(self, hits: int) -> float | None:
        return hits / self.scored if self.scored else None

    @property
    def pass_rate(self) -> float | None:
        return self.rate(self.counts[Verdict.PASS])

    @property
    def asr(self) -> float | None:
        return self.rate(self.counts[Verdict.FAIL])

    @property
    def refused(self) -> int:
        return self.counts[Verdict.REFUSED]

    @property
    def refusal_rate(self) -> float | None:
        """Runs the target's API refused, over every run (not scored runs)."""
        return self.refused / self.runs if self.runs else None

    @property
    def detection_rate(self) -> float | None:
        return self.rate(self.detected)

    @property
    def influenced(self) -> int:
        """Runs where the attack swayed the target without a rule-breaking
        action: it offered, asked or claimed to comply (Partial), or a
        human must decide (Review)."""
        return self.counts[Verdict.PARTIAL] + self.counts[Verdict.REVIEW]

    @property
    def outright(self) -> int:
        """Partial runs recorded as offering the attacker's action outright."""
        return self.partial_known - self.confirm_first

    @property
    def influenced_rate(self) -> float | None:
        return self.rate(self.influenced)

    @property
    def low_sample(self) -> bool:
        return self.scored < LOW_SAMPLE


@dataclass
class AttackRow:
    label: str
    name: str
    category: str
    severity: str
    atlas: list[str]
    tally: Tally = field(default_factory=Tally)
    # The payload variant id and kind; '' for the attack's own payload.
    variant: str = ""
    variant_kind: str = ""
    # Adaptive runs only: attacker calls, and calls that wrote no payload.
    attacker_calls: int = 0
    attacker_refused: int = 0

    @property
    def attacker_refusal_rate(self) -> float | None:
        return self.attacker_refused / self.attacker_calls if self.attacker_calls else None


@dataclass
class CategoryRow:
    category: str
    name: str
    attacks: list[AttackRow] = field(default_factory=list)
    tally: Tally = field(default_factory=Tally)


@dataclass
class TechniqueRow:
    technique: str
    name: str
    attacks: set[str] = field(default_factory=set)
    tally: Tally = field(default_factory=Tally)


@dataclass
class VersionRow:
    label: str
    version: int
    policy: str | None
    tally: Tally
    runs: list[Run]


@dataclass
class VariantGroup:
    """One attack version: its own payload's row, then each variant's."""

    label: str
    name: str
    rows: list[AttackRow]


@dataclass
class PolicyComparison:
    """One attack run under more than one version, side by side."""

    attack_id: str
    name: str
    versions: list[VersionRow]


@dataclass
class Report:
    target: str
    judges: Counter
    first: datetime
    last: datetime
    runs: list[Run]
    total: Tally
    attacks: list[AttackRow]
    categories: list[CategoryRow]
    techniques: list[TechniqueRow]
    findings: list[Run]
    comparisons: list[PolicyComparison] = field(default_factory=list)
    # Attack versions run with payload variants, base row first.
    variant_groups: list[VariantGroup] = field(default_factory=list)
    # Runs with an exposure record, and the runs that have exposure.
    exposure_checked: int = 0
    exposed_runs: list[Run] = field(default_factory=list)

    @property
    def adaptive(self) -> bool:
        """True when the runs are adaptive (build_report never mixes the two)."""
        return any(r.adaptive for r in self.runs)

    @property
    def attackers(self) -> list[str]:
        return sorted({r.record["adaptive"]["attacker"] for r in self.runs if r.adaptive})

    @property
    def attacker_tested(self) -> int:
        """Adaptive runs an attacker payload reached; the rest are single-shot."""
        return sum(r.attacker_tested for r in self.runs)

    @property
    def attacker_calls(self) -> int:
        return sum(r.attacker_calls for r in self.runs)

    @property
    def attacker_refused(self) -> int:
        return sum(r.attacker_refused for r in self.runs)


def load_runs(paths: list[str | Path]) -> list[Run]:
    """Lure result files: each file given, plus *.json directly in each
    folder. Files that are not Lure results are skipped."""
    runs = []
    for path in record_paths(paths):
        try:
            run = Run(path, json.loads(path.read_text(encoding="utf-8")))
            # Touch every field the report reads, so a bad file is skipped here.
            _ = (run.key, run.verdict, run.started_at, run.record["target"],
                 run.attack["name"], run.attack["category"], run.attack["atlas"])
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            continue
        runs.append(run)
    return runs


def build_report(runs: list[Run], target: str | None = None) -> Report:
    targets = sorted({r.record["target"] for r in runs})
    if target is not None:
        runs = [r for r in runs if r.record["target"] == target]
        if not runs:
            raise ReportError(f"no runs for target {target!r}; found: {', '.join(targets)}")
    elif len(targets) > 1:
        raise ReportError("results cover more than one target; pick one with --target: "
                          + ", ".join(targets))
    if not runs:
        raise ReportError("no Lure results found")
    if len({r.adaptive for r in runs}) > 1:
        raise ReportError("results mix adaptive and single-shot runs; report them separately "
                          "(worst of several attempts is not comparable with one attempt)")

    total = Tally()
    # One row per attack version, variant and mode, so an adaptive run no
    # attacker payload reached never shares a row with attacker-tested runs.
    attacks: dict[tuple[tuple[str, int], str, str], AttackRow] = {}
    techniques: dict[str, TechniqueRow] = {}
    for run in sorted(runs, key=lambda r: (r.key, r.variant, r.mode, r.started_at)):
        total.add(run)
        a = run.attack
        row = attacks.setdefault((run.key, run.variant, run.mode), AttackRow(
            run.label, a["name"], a["category"], a.get("severity", "medium"), list(a["atlas"]),
            variant=run.variant, variant_kind=run.variant_kind))
        row.tally.add(run)
        row.attacker_calls += run.attacker_calls
        row.attacker_refused += run.attacker_refused
        for t in a["atlas"]:
            trow = techniques.setdefault(t, TechniqueRow(t, atlas_name(t)))
            trow.attacks.add(run.label)
            trow.tally.add(run)

    categories: dict[str, CategoryRow] = {}
    for row in attacks.values():
        cat = categories.setdefault(row.category, CategoryRow(row.category, category_name(row.category)))
        cat.attacks.append(row)
        for v, n in row.tally.counts.items():
            cat.tally.counts[v] += n
        cat.tally.detected += row.tally.detected
        cat.tally.exposed += row.tally.exposed
        cat.tally.exposure_calls += row.tally.exposure_calls
        cat.tally.confirm_first += row.tally.confirm_first
        cat.tally.partial_known += row.tally.partial_known

    findings = sorted(
        (r for r in runs if r.verdict in FINDING_VERDICTS),
        key=lambda r: (r.rank, SEVERITY_ORDER.get(r.attack.get("severity"), 9),
                       r.key, r.started_at),
    )
    # Highest ASR first, then highest influenced rate, then the most tested.
    technique_rows = sorted(techniques.values(), key=lambda t: (
        -(t.tally.asr or 0), -(t.tally.influenced_rate or 0), -t.tally.runs, t.technique))
    return Report(
        target=runs[0].record["target"],
        judges=Counter(r.judge for r in runs),
        first=min(r.started_at for r in runs),
        last=max(r.started_at for r in runs),
        runs=runs,
        total=total,
        attacks=list(attacks.values()),
        categories=sorted(categories.values(), key=lambda c: c.name),
        techniques=technique_rows,
        findings=findings,
        comparisons=_comparisons(runs, attacks),
        variant_groups=_variant_groups(attacks),
        exposure_checked=sum(r.exposure_checked for r in runs),
        exposed_runs=sorted((r for r in runs if r.exposure_calls),
                            key=lambda r: (r.key, r.started_at)),
    )


def _variant_groups(attacks: dict[tuple[tuple[str, int], str, str], AttackRow],
                    ) -> list[VariantGroup]:
    by_key: dict[tuple[tuple[str, int], str], list[AttackRow]] = {}
    for (key, _, mode), row in attacks.items():
        by_key.setdefault((key, mode), []).append(row)
    groups = []
    for ((attack_id, version), mode), rows in sorted(by_key.items()):
        if any(r.variant for r in rows):
            rows = sorted(rows, key=lambda r: (r.variant != "", r.variant))
            label = f"{attack_id} v{version}" + (f" {mode}" if mode else "")
            groups.append(VariantGroup(label, rows[0].name, rows))
    return groups


def _comparisons(runs: list[Run], attacks: dict[tuple[tuple[str, int], str, str], AttackRow],
                 ) -> list[PolicyComparison]:
    """Versions side by side, on each attack's own payload only."""
    by_id: dict[str, list[tuple[tuple[str, int], str]]] = {}
    for key, variant, mode in attacks:
        if not variant:
            by_id.setdefault(key[0], []).append((key, mode))
    out = []
    for attack_id, row_keys in sorted(by_id.items()):
        if len({key[1] for key, _ in row_keys}) < 2:
            continue
        rows = []
        for row_key in sorted(row_keys, key=lambda k: (k[0][1], k[1])):
            key, mode = row_key
            version_runs = sorted((r for r in runs
                                   if r.key == key and r.mode == mode and not r.variant),
                                  key=lambda r: r.started_at)
            row = attacks[(key, "", mode)]
            rows.append(VersionRow(row.label, key[1], version_runs[0].policy,
                                   row.tally, version_runs))
        last_key, last_mode = row_keys[-1]
        out.append(PolicyComparison(attack_id, attacks[(last_key, "", last_mode)].name, rows))
    return out
