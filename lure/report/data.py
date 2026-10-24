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
                 Verdict.INVALID, Verdict.FAIL, Verdict.ERROR)
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
        """Always names the version, v1 included, so versions never blur."""
        attack_id, version = self.key
        return f"{attack_id} v{version}"

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
    # Runs with an exposure record, and the runs that have exposure.
    exposure_checked: int = 0
    exposed_runs: list[Run] = field(default_factory=list)


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

    total = Tally()
    attacks: dict[tuple[str, int], AttackRow] = {}
    techniques: dict[str, TechniqueRow] = {}
    for run in sorted(runs, key=lambda r: (r.key, r.started_at)):
        total.add(run)
        a = run.attack
        row = attacks.setdefault(run.key, AttackRow(
            run.label, a["name"], a["category"], a.get("severity", "medium"), list(a["atlas"])))
        row.tally.add(run)
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
        exposure_checked=sum(r.exposure_checked for r in runs),
        exposed_runs=sorted((r for r in runs if r.exposure_calls),
                            key=lambda r: (r.key, r.started_at)),
    )


def _comparisons(runs: list[Run], attacks: dict[tuple[str, int], AttackRow]) -> list[PolicyComparison]:
    by_id: dict[str, list[tuple[str, int]]] = {}
    for key in attacks:
        by_id.setdefault(key[0], []).append(key)
    out = []
    for attack_id, keys in sorted(by_id.items()):
        if len(keys) < 2:
            continue
        rows = []
        for key in sorted(keys, key=lambda k: k[1]):
            version_runs = sorted((r for r in runs if r.key == key), key=lambda r: r.started_at)
            rows.append(VersionRow(attacks[key].label, key[1], version_runs[0].policy,
                                   attacks[key].tally, version_runs))
        out.append(PolicyComparison(attack_id, attacks[keys[-1]].name, rows))
    return out
