"""Render the report as one static HTML file: inline CSS, no scripts, no
external requests. Every value from the results is escaped, since replies
and payloads are attack text by design."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, PackageLoader, StrictUndefined

from lure.judge.rules import Verdict
from lure.report.data import VERDICT_ORDER, Report
from lure.report.exec_summary import (
    exec_summary,
    headline,
    model_name,
    pct,
    policy_comparison,
    what_it_did,
    why,
)
from lure.report.techniques import atlas_name, category_name

# Symbol and word per verdict; color is never the only cue.
VERDICT_MARKS = {
    Verdict.PASS: "✓",      # check mark
    Verdict.PARTIAL: "◐",   # half-filled circle
    Verdict.REVIEW: "?",
    Verdict.INVALID: "–",   # en dash
    Verdict.FAIL: "✕",      # multiplication x
    Verdict.ERROR: "!",
}
# Fill steps 1 to 8 for a rate cell (.asr-N in the template). Exactly 0% is
# unfilled so "nothing happened" recedes; anything above gets at least step 1.
ASR_STEPS = 8


def asr_step(rate: float | None) -> str:
    if rate is None:
        return "asr-na"
    if rate == 0:
        return "asr-zero"
    return f"asr-{max(1, min(ASR_STEPS, 1 + round(rate * (ASR_STEPS - 1))))}"


def judge_name(judge: str) -> str:
    """'anthropic:claude-sonnet-5-5' -> 'claude-sonnet-5-5'; 'rules' -> 'rules only'."""
    return "rules only" if judge == "rules" else judge.split(":", 1)[-1]


def pretty_args(args: dict) -> str:
    """One `name: value` line per argument. Text keeps its own line breaks
    (an email body reads as it was sent); lists of text join with commas;
    anything else is JSON. Values are never shortened."""
    lines = []
    for name, value in args.items():
        if isinstance(value, str) and "\n" in value:
            lines.append(f"{name}:")
            lines += [f"  {line}" for line in value.split("\n")]
        elif isinstance(value, str):
            lines.append(f"{name}: {value}")
        elif isinstance(value, list) and value and all(isinstance(v, str) for v in value):
            lines.append(f"{name}: {', '.join(value)}")
        else:
            lines.append(f"{name}: {json.dumps(value, ensure_ascii=False)}")
    return "\n".join(lines) if lines else "(no arguments)"


SENTENCE_RE = re.compile(r"(?<=[.!?])\s+")


def policy_segments(versions: list) -> list[list[tuple[str, bool]]]:
    """Split each version's policy into sentences, marking each one shared
    (in every version) or its own, so only the difference stands out."""
    split = [[t for t in SENTENCE_RE.split((v.policy or "").strip()) if t] for v in versions]
    shared = set.intersection(*(set(s) for s in split)) if split else set()
    return [[(t, t in shared) for t in sentences] for sentences in split]


def date_range(first: datetime, last: datetime) -> str:
    a, b = first.strftime("%B %-d, %Y"), last.strftime("%B %-d, %Y")
    return a if a == b else f"{a} to {b}"


def render(report: Report, generated: datetime | None = None) -> str:
    env = Environment(
        loader=PackageLoader("lure.report", "templates"),
        autoescape=True,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters.update(pct=pct, asr_step=asr_step, pretty_args=pretty_args,
                       atlas_name=atlas_name, category_name=category_name)
    template = env.get_template("report.html.j2")
    return template.render(
        report=report,
        model=model_name(report.target),
        headline=headline(report),
        summary=exec_summary(report),
        comparison_lines=policy_comparison(report),
        what_it_did=what_it_did,
        policy_segments=policy_segments,
        policy_files=sorted({(r.record.get("exposure") or {}).get("policy", "lure.yaml")
                             for r in report.runs if r.exposure_checked}),
        verdicts=VERDICT_ORDER,
        marks=VERDICT_MARKS,
        why=why,
        Verdict=Verdict,
        dates=date_range(report.first, report.last),
        judge_names=[(judge_name(j), n) for j, n in report.judges.most_common()],
        judge_name=judge_name,
        generated=(generated or datetime.now(UTC)).strftime("%Y-%m-%d %H:%M UTC"),
    )


def write_report(report: Report, out: str | Path) -> Path:
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(report), encoding="utf-8")
    return out
