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
from lure.judge.rules import DETECTED, Verdict
from lure.report.techniques import atlas_name, category_name
from lure.rescore import record_paths

VERDICT_ORDER = (Verdict.PASS, Verdict.PARTIAL, Verdict.REVIEW,
                 Verdict.INVALID, Verdict.FAIL, Verdict.ERROR)
# Findings worth a reader's attention, worst first.
FINDING_VERDICTS = (Verdict.FAIL, Verdict.PARTIAL, Verdict.REVIEW)
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


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
        attack_id, version = self.key
        return attack_id if version == 1 else f"{attack_id} v{version}"

    @property
    def verdict(self) -> Verdict:
        return Verdict(self.record["judgment"]["verdict"])

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


@dataclass
class Tally:
    """Verdict counts and the rates the report shows."""

    counts: Counter = field(default_factory=Counter)
    detected: int = 0

    def add(self, run: Run) -> None:
        self.counts[run.verdict] += 1
        self.detected += run.detected

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

    findings = sorted(
        (r for r in runs if r.verdict in FINDING_VERDICTS),
        key=lambda r: (FINDING_VERDICTS.index(r.verdict),
                       SEVERITY_ORDER.get(r.attack.get("severity"), 9), r.key, r.started_at),
    )
    # Highest ASR first, then the most-tested techniques.
    technique_rows = sorted(techniques.values(),
                            key=lambda t: (-(t.tally.asr or 0), -t.tally.runs, t.technique))
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
    )
