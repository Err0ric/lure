"""Batch helpers: find attack files and summarize many runs per attack."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from lure.attacks import AttackError
from lure.judge.rules import Verdict
from lure.runner import RunResult

# Runs that did not test the target. Left out of rate denominators.
UNSCORED = (Verdict.INVALID, Verdict.ERROR)


def collect_attack_paths(path: str | Path) -> list[Path]:
    """Return [path] for a file, or every *.yaml under a folder, sorted."""
    path = Path(path)
    if path.is_file():
        return [path]
    if path.is_dir():
        found = sorted(p for p in path.rglob("*.yaml") if p.is_file())
        if not found:
            raise AttackError(f"no attack files (*.yaml) found under {path}")
        return found
    raise AttackError(f"attack file not found: {path}")


@dataclass
class SummaryRow:
    attack_id: str
    counts: Counter = field(default_factory=Counter)
    # (verdict, reason) -> runs, for Invalid and Error runs.
    unscored_reasons: Counter = field(default_factory=Counter)

    @property
    def runs(self) -> int:
        return sum(self.counts.values())

    @property
    def scored(self) -> int:
        return self.runs - sum(self.counts[v] for v in UNSCORED)

    @property
    def pass_rate(self) -> float | None:
        return self.counts[Verdict.PASS] / self.scored if self.scored else None

    @property
    def asr(self) -> float | None:
        """Attack success rate: Fail / scored runs."""
        return self.counts[Verdict.FAIL] / self.scored if self.scored else None


def summarize(results: list[RunResult]) -> list[SummaryRow]:
    """One row per attack id, in first-seen order."""
    rows: dict[str, SummaryRow] = {}
    for r in results:
        row = rows.setdefault(r.attack.id, SummaryRow(r.attack.id))
        row.counts[r.judgment.verdict] += 1
        if r.judgment.verdict in UNSCORED:
            row.unscored_reasons[(r.judgment.verdict, r.judgment.reason)] += 1
    return list(rows.values())
