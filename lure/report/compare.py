"""Compare targets side by side: one results folder per target.

Each folder is built into its own Report first, so every rate here is the
same number that target's own report shows. Token counts come from the
saved runs: the target's usage, and the LLM judge's usage kept in each
judgment. Dollars appear only with a prices file; Lure ships no rates.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from lure.judge.rules import Verdict
from lure.prices import (  # noqa: F401 (re-exported)
    INPUT_KEYS,
    PRICE_FIELDS,
    Prices,
    PricesError,
    load_prices,
)
from lure.report.data import (
    AttackRow,
    Report,
    ReportError,
    Tally,
    VersionRow,
    build_report,
    load_runs,
)
from lure.report.exec_summary import model_name, pct, plural


@dataclass
class Usage:
    """Token totals for one model, as recorded in the runs."""

    model: str
    tokens: Counter = field(default_factory=Counter)
    runs: int = 0

    def add(self, usage: dict[str, int]) -> None:
        self.tokens.update({k: v for k, v in usage.items() if isinstance(v, int)})
        self.runs += 1

    @property
    def input(self) -> int:
        """Every input token, cached or not."""
        return sum(self.tokens[k] for k in INPUT_KEYS)

    @property
    def cached(self) -> int:
        return self.tokens["cache_creation_input_tokens"] + self.tokens["cache_read_input_tokens"]

    @property
    def output(self) -> int:
        return self.tokens["output_tokens"]


@dataclass
class Column:
    """One target: its report and the tokens it and its judge used."""

    source: str
    report: Report
    target_usage: Usage
    judge_usage: list[Usage]
    # The adaptive attacker's usage, one per attacker model. Empty if none.
    attacker_usage: list[Usage] = field(default_factory=list)

    @property
    def model(self) -> str:
        return model_name(self.report.target)

    @property
    def attacks(self) -> dict[str, AttackRow]:
        return {a.label: a for a in self.report.attacks}

    def target_cost(self, prices: Prices | None) -> float | None:
        return prices.cost(self.target_usage.model, self.target_usage.tokens) if prices else None

    def judge_cost(self, prices: Prices | None) -> float | None:
        """None if any judge model used tokens and has no price."""
        if not prices:
            return None
        costs = [prices.cost(u.model, u.tokens) for u in self.judge_usage]
        return None if None in costs else sum(costs)

    def attacker_cost(self, prices: Prices | None) -> float | None:
        """0 with no attacker; None if an attacker model has no price."""
        if not prices:
            return None
        costs = [prices.cost(u.model, u.tokens) for u in self.attacker_usage]
        return None if None in costs else sum(costs)


@dataclass
class CategoryCompare:
    category: str
    name: str
    # One tally per column, None where that target ran no attack of this category.
    tallies: list[Tally | None]


@dataclass
class VersionCompare:
    label: str
    version: int
    policy: str | None
    # One row per column, None where that target did not run this version.
    rows: list[VersionRow | None]


@dataclass
class PolicyCompare:
    """One attack run under more than one version, across targets."""

    attack_id: str
    name: str
    versions: list[VersionCompare]


@dataclass
class Comparison:
    columns: list[Column]
    categories: list[CategoryCompare]
    policies: list[PolicyCompare]
    # Attack labels each target did not run that another target did.
    missing: dict[str, list[str]]
    prices: Prices | None = None

    @property
    def first(self) -> datetime:
        return min(c.report.first for c in self.columns)

    @property
    def last(self) -> datetime:
        return max(c.report.last for c in self.columns)

    @property
    def judges(self) -> list[str]:
        """The judge setting per column, as recorded: one name, or Mixed."""
        out = []
        for c in self.columns:
            names = [j for j, _ in c.report.judges.most_common()]
            out.append(names[0] if len(names) == 1 else "mixed")
        return out

    @property
    def judges_differ(self) -> bool:
        return len(set(self.judges)) > 1

    @property
    def exposure_checked(self) -> bool:
        return all(c.report.exposure_checked for c in self.columns)

    @property
    def adaptive(self) -> bool:
        return any(c.report.adaptive for c in self.columns)


def build_comparison(sources: list[str | Path], prices: Prices | None = None) -> Comparison:
    if len(sources) < 2:
        raise ReportError("compare needs at least two results folders, one per target")
    columns: list[Column] = []
    for source in sources:
        runs = load_runs([source])
        if not runs:
            raise ReportError(f"no Lure results found in {source}")
        try:
            report = build_report(runs)
        except ReportError as e:
            raise ReportError(f"{source}: {e}; compare takes one folder per target") from None
        columns.append(_column(str(source), report))
    modes = {c.report.adaptive for c in columns}
    if len(modes) > 1:
        raise ReportError("compare adaptive runs only with adaptive runs: worst of several "
                          "attempts is not comparable with a single attempt")
    seen: dict[str, str] = {}
    for c in columns:
        if c.report.target in seen:
            raise ReportError(f"{seen[c.report.target]} and {c.source} are both "
                              f"{c.report.target}; compare takes one folder per target")
        seen[c.report.target] = c.source

    labels = sorted({label for c in columns for label in c.attacks})
    missing = {c.model: [l for l in labels if l not in c.attacks] for c in columns}
    return Comparison(
        columns=columns,
        categories=_categories(columns),
        policies=_policies(columns),
        missing={m: ls for m, ls in missing.items() if ls},
        prices=prices,
    )


def _column(source: str, report: Report) -> Column:
    target = Usage(report.target)
    judges: dict[str, Usage] = {}
    attackers: dict[str, Usage] = {}
    for run in report.runs:
        adaptive = run.record.get("adaptive")
        # An adaptive run spent tokens on every attempt, not only the one it mirrors.
        scored = [a for a in adaptive["attempts"] if "judgment" in a] if adaptive else [run.record]
        for attempt in scored:
            target.add(attempt.get("usage") or {})
            llm = attempt["judgment"].get("llm_judge") or {}
            if llm.get("usage"):
                model = llm.get("model") or run.judge
                judges.setdefault(model, Usage(model)).add(llm["usage"])
        if adaptive and adaptive["usage"]["attacker"]:
            model = adaptive["attacker"]
            attackers.setdefault(model, Usage(model)).add(adaptive["usage"]["attacker"])
    return Column(source, report, target, sorted(judges.values(), key=lambda u: u.model),
                  sorted(attackers.values(), key=lambda u: u.model))


def _categories(columns: list[Column]) -> list[CategoryCompare]:
    names = {cat.category: cat.name for c in columns for cat in c.report.categories}
    out = []
    for category, name in sorted(names.items(), key=lambda kv: kv[1]):
        tallies = []
        for c in columns:
            row = next((cat for cat in c.report.categories if cat.category == category), None)
            tallies.append(row.tally if row else None)
        out.append(CategoryCompare(category, name, tallies))
    return out


def _policies(columns: list[Column]) -> list[PolicyCompare]:
    """Every attack that any target ran under more than one version."""
    by_id: dict[str, dict[int, list[VersionRow | None]]] = {}
    names: dict[str, str] = {}
    for i, c in enumerate(columns):
        for comp in c.report.comparisons:
            names.setdefault(comp.attack_id, comp.name)
            for v in comp.versions:
                rows = by_id.setdefault(comp.attack_id, {}).setdefault(v.version, [None] * len(columns))
                rows[i] = v
    out = []
    for attack_id, versions in sorted(by_id.items()):
        vcs = []
        for version, rows in sorted(versions.items()):
            present = [r for r in rows if r is not None]
            policy = next((r.policy for r in present if r.policy), None)
            vcs.append(VersionCompare(present[0].label, version, policy, rows))
        out.append(PolicyCompare(attack_id, names[attack_id], vcs))
    return out


def compare_headline(comp: Comparison) -> str:
    """The one-sentence answer at the top of the page."""
    totals = [(c.model, c.report.total) for c in comp.columns]
    if not any(t.counts[Verdict.FAIL] for _, t in totals):
        return ("No target broke an attack's rules; "
                + _join(f"{m} was influenced in {pct(t.influenced_rate)}" for m, t in totals)
                + " of scored runs.")
    return "Attack success rate: " + _join(f"{m} {pct(t.asr)}" for m, t in totals) + "."


def compare_lede(comp: Comparison) -> list[str]:
    """Short factual lines under the headline."""
    lines = []
    if comp.exposure_checked:
        lines.append("Exposure: " + _join(
            f"{c.model} sent outside the allowed domains in {plural(c.report.total.exposed, 'run')}"
            for c in comp.columns) + ".")
    if comp.judges_differ:
        lines.append("The targets were scored by different judge models. Rule verdicts do not "
                     "depend on the judge, but a Partial or Review the LLM judge decided can, "
                     "so small differences in influenced rate may come from the judge.")
    for model, labels in comp.missing.items():
        lines.append(f"{model} has no runs of {', '.join(labels)}; its rates cover fewer attacks.")
    return lines


def _join(parts: Iterable[str]) -> str:
    parts = list(parts)
    if len(parts) <= 2:
        return " and ".join(parts)
    return ", ".join(parts[:-1]) + ", and " + parts[-1]
