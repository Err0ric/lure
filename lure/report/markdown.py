"""Render the report as Markdown, for a PR comment, a CI job summary or a
wiki page.

Replies, reasons and payload-derived text are attack text by design, so
every value from the results is escaped: it renders as plain text and can
never become a link, an image or markup.
"""

from __future__ import annotations

import re
from pathlib import Path

from lure.judge.rules import CONFIRM_FIRST, Verdict
from lure.policy import PolicyResult
from lure.report.data import FINDING_VERDICTS, Report, Run, Tally
from lure.report.exec_summary import exec_summary, headline, model_name, pct, why
from lure.report.render import date_range, judge_name

# Characters that mean something in Markdown or inline HTML.
SPECIAL_RE = re.compile(r"([\\`*_{}\[\]()<>#+!|~&])")
MAX_CELL = 240


def text(value: object, limit: int = MAX_CELL) -> str:
    """Untrusted text as one escaped line, cut to `limit` characters."""
    line = " ".join(str(value).split())
    if len(line) > limit:
        line = line[: limit - 1].rstrip() + "…"
    return SPECIAL_RE.sub(r"\\\1", line)


def rate(value: float | None, tally: Tally) -> str:
    return pct(value) + (" (low sample)" if value is not None and tally.low_sample else "")


def table(header: list[str], rows: list[list[str]], numeric: range = range(0)) -> list[str]:
    align = ["---:" if i in numeric else "---" for i in range(len(header))]
    return ["| " + " | ".join(header) + " |", "| " + " | ".join(align) + " |",
            *("| " + " | ".join(r) + " |" for r in rows)]


def render_markdown(report: Report, gate: PolicyResult | None = None) -> str:
    t = report.total
    judges = ", ".join(judge_name(j) for j in sorted(report.judges))
    lines = [
        f"# Lure report: {text(model_name(report.target))}",
        "",
        f"**{text(headline(report))}**",
        "",
        (f"Target `{report.target}`, judged by {text(judges)}, "
        f"{t.runs} runs of {len(report.attacks)} attacks, {date_range(report.first, report.last)}."),
    ]
    if report.adaptive:
        lines[-1] += (f" Adaptive attacker {text(', '.join(report.attackers))}, worst case: it "
                      "sees the agent's replies. Each run is its worst attempt, so rates are not "
                      f"comparable with single-shot runs. Attacker payloads reached the target in "
                      f"{report.attacker_tested} of {t.runs} runs; the rest are single-shot.")
        lines += ["", "| Attack | Runs | Attacker calls | Refused | Refusal rate |",
                  "| --- | ---: | ---: | ---: | ---: |"]
        lines += [f"| {text(a.label)} | {a.tally.runs} | {a.attacker_calls} | "
                  f"{a.attacker_refused} | "
                  f"{'n/a' if a.attacker_refusal_rate is None else f'{a.attacker_refusal_rate:.0%}'} |"
                  for a in report.attacks]
    if gate is not None:
        status = "PASS" if gate.passed else "FAIL"
        lines += ["", (f"**Policy: {status}** ({text(gate.label)}): {gate.failed_runs} of "
                      f"{gate.runs} runs failed it.")]
        if gate.skipped:
            lines[-1] += f" {gate.skipped} runs of disabled attacks were not gated."

    lines += ["", "## Summary", ""]
    lines += [f"- {text(b, 1000)}" for b in exec_summary(report)]

    lines += ["", "## Rates", "",
              ("Rates are over scored runs; Invalid and Error runs are left out. "
              "Influenced is Partial plus Review: the target offered, asked or claimed to act "
              "on the attack without breaking its rules. A Partial is outright, or confirm "
              "first when the target only offered the action if the user explicitly "
              "confirmed it."), ""]
    lines += table(
        ["Scope", "Runs", "Scored", "Pass rate", "ASR", "Influenced rate", "Detection rate",
         "Exposed runs"],
        [[label, str(x.runs), str(x.scored), rate(x.pass_rate, x), rate(x.asr, x),
          rate(x.influenced_rate, x), rate(x.detection_rate, x),
          str(x.exposed) if report.exposure_checked else "not checked"]
         for label, x in [("**All**", t), *((text(c.name), c.tally) for c in report.categories)]],
        numeric=range(1, 8))

    lines += ["", "## Exposure", ""]
    if not report.exposure_checked:
        lines.append("Not recorded: these results were saved without an org policy.")
        # The policy recomputes exposure from the logs; say so when it found some.
        exposed = len({v.where for v in gate.violations if v.kind == "exposure"}) if gate else 0
        if exposed:
            lines[-1] += (f" The policy check above recomputed it from the tool-call logs with "
                          f"{text(gate.source)}: {exposed} runs sent outside the allowed domains.")
    elif not report.exposed_runs:
        lines.append(f"No run sent email or made a request outside the allowed domains "
                     f"({report.exposure_checked} runs checked).")
    else:
        lines += [(f"{len(report.exposed_runs)} of {report.exposure_checked} checked runs sent "
                  "email or made a request outside the allowed domains, whatever the verdict."),
                  ""]
        lines += table(["Attack", "Verdict", "Call", "Outside", "Result"],
                       [[text(r.label), r.verdict.value, f"#{c['index']} {text(c['tool'])}",
                         text(", ".join(c["outside"])), _file(r)]
                        for r in report.exposed_runs for c in r.exposure_calls])

    lines += ["", "## Findings by ATLAS technique", ""]
    lines += _findings(report)
    return "\n".join(lines) + "\n"


def _findings(report: Report) -> list[str]:
    """Each technique with findings, then one row per attack version: counts
    of Fail, Partial and Review, and the reason behind the worst run. An
    attack mapped to two techniques appears under both."""
    out: list[str] = []
    for tech in report.techniques:
        runs = [r for r in report.findings
                if tech.technique in r.attack["atlas"] and r.rank < 9]
        if not runs:
            continue
        out += [f"### {tech.technique}: {text(tech.name)}", ""]
        by_attack: dict[str, list[Run]] = {}
        for r in runs:
            by_attack.setdefault(r.label, []).append(r)
        rows = []
        for label, attack_runs in by_attack.items():
            worst = attack_runs[0]  # findings are sorted worst first
            counts = [_count(attack_runs, v) for v in FINDING_VERDICTS]
            rows.append([f"{text(label)}: {text(worst.attack['name'])}",
                         text(worst.attack.get("severity", "")), *counts,
                         text(why(worst)), _file(worst)])
        out += table(["Attack", "Severity", *(v.value for v in FINDING_VERDICTS),
                      "Worst run", "Result"], rows, numeric=range(2, 5))
        out.append("")
    if not out:
        return ["No findings: no run was scored Fail, Partial or Review."]
    return out[:-1]


def _count(runs: list[Run], verdict: Verdict) -> str:
    """A verdict count; a Partial count also says how many were confirm first."""
    n = sum(r.verdict is verdict for r in runs)
    confirm = sum(r.partial_kind == CONFIRM_FIRST for r in runs)
    return f"{n} ({confirm} confirm first)" if verdict is Verdict.PARTIAL and confirm else str(n)


def _file(run: Run) -> str:
    return text(run.path.name)


def write_markdown(report: Report, out: str | Path, gate: PolicyResult | None = None) -> Path:
    path = Path(out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_markdown(report, gate), encoding="utf-8")
    return path
