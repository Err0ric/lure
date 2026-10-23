"""Five plain-language bullets for a non-technical reader.

Built only from the aggregated results, so every claim traces back to a
verdict in the report below it. No model writes this text.
"""

from __future__ import annotations

from lure.judge.rules import Verdict
from lure.report.data import FINDING_VERDICTS, Report, Run, Tally, VersionRow
from lure.report.techniques import category_name

# One guardrail per weakest area, phrased as an action a team can take.
GUARDRAILS = {
    "indirect_prompt_injection": (
        "Treat email and web content as data, not instructions: require a person to "
        "approve any action that a message or page asks the agent to take."
    ),
    "direct_prompt_injection": (
        "Write agent policies as allow-lists (\"only email corp.example\") and keep "
        "secrets out of the system prompt."
    ),
    "jailbreak": (
        "Enforce outbound rules in the tools, not only in the prompt: block email to "
        "outside domains at the send step, whatever the agent was talked into."
    ),
    "data_leakage": (
        "Check outbound email for internal-only data (approval codes, account numbers, "
        "other vendors' figures) before it is sent."
    ),
    "tool_abuse": (
        "Require human approval for payments, deletes and bank-detail changes."
    ),
}


def pct(rate: float | None) -> str:
    return "n/a" if rate is None else f"{rate:.0%}"


def plural(n: int, word: str, many: str | None = None) -> str:
    return f"{n} {word if n == 1 else (many or word + 's')}"


def model_name(target: str) -> str:
    """'anthropic:claude-haiku-5-5' -> 'claude-haiku-5-5'."""
    return target.split(":", 1)[1] if ":" in target else target


def why(run: Run) -> str:
    """The judge's one-line reason; else the reply text the rules matched;
    else the rules' reason."""
    judgment = run.record["judgment"]
    llm = judgment.get("llm_judge") or {}
    if llm.get("justification"):
        return llm["justification"]
    quoted = [t for e in judgment.get("evidence", []) for t in e.get("text", [])]
    if quoted and run.verdict is Verdict.PARTIAL:
        return f"It asked: \u201c{quoted[0]}\u201d"
    return judgment["reason"][:1].upper() + judgment["reason"][1:] + "."


def rate_text(rate: float | None, tally: Tally) -> str:
    """A rate with its low-sample warning, for prose."""
    return pct(rate) + (", low sample" if tally.low_sample else "")


def headline(report: Report) -> str:
    """The one-sentence answer at the top of the report. Harm is whatever
    each attack's rules define, so the wording says rules, not harm."""
    model, total = model_name(report.target), report.total
    fails = total.counts[Verdict.FAIL]
    if not fails:
        return (f"{model}: no run broke its attack's rules in "
                f"{plural(total.scored, 'scored attack run')}.")
    return (f"{model} broke its attack's rules in {fails} of "
            f"{plural(total.scored, 'scored attack run')}.")


def what_it_did(row: VersionRow) -> str:
    """Plain counts for one attack version, plus the judge's reason for its
    most serious run."""
    t = row.tally
    parts = [f"broke the rules in {t.counts[Verdict.FAIL]}",
             f"was influenced in {t.influenced}",
             f"flagged the attack in {t.detected}"]
    text = f"Of {plural(t.scored, 'scored run')}, it " + ", ".join(parts) + "."
    worst = min((r for r in row.runs if r.verdict in FINDING_VERDICTS and r.rank < 9),
                key=lambda r: r.rank, default=None)
    return f"{text} {why(worst)}" if worst else text


def policy_comparison(report: Report) -> list[str]:
    """One sentence per attack that ran under more than one version."""
    lines = []
    for c in report.comparisons:
        parts = [f"Under v{v.version} it was influenced in {v.tally.influenced} of "
                 f"{v.tally.scored} runs ({rate_text(v.tally.influenced_rate, v.tally)})."
                 for v in c.versions]
        lines.append(f"{c.attack_id} ({c.name}) ran the same attack text under "
                     f"{len(c.versions)} system prompts. " + " ".join(parts))
    return lines


def exec_summary(report: Report) -> list[str]:
    total = report.total
    fails = total.counts[Verdict.FAIL]
    n_attacks = len(report.attacks)
    bullets = []

    if fails:
        bullets.append(
            f"{fails} of {total.scored} scored runs across {plural(n_attacks, 'attack')} broke "
            f"the attack's rules: an attack success rate of {rate_text(total.asr, total)}."
        )
    else:
        bullets.append(
            f"No run broke its attack's rules: across {plural(total.scored, 'scored run')} of "
            f"{plural(n_attacks, 'attack')}, the tool log shows none of the actions the "
            f"attacks were written to catch."
        )

    bullets.append(
        f"It recognized the attack and said so in {total.detected} of {total.scored} runs "
        f"({rate_text(total.detection_rate, total)}). The attack influenced it in "
        f"{plural(total.influenced, 'run')} ({rate_text(total.influenced_rate, total)}): it "
        f"offered, asked or claimed to carry out the request without the action showing in "
        f"the tool log."
    )

    candidates = [f for f in report.findings if f.rank < 9]
    worst = candidates[0] if candidates else None
    if worst is None:
        bullets.append("No run needed follow-up: there were no failures, near misses or "
                       "undecided results.")
    else:
        kind = {0: "Worst finding", 1: "Closest call", 2: "Needs a human look",
                3: "Closest call (rules only, not confirmed by the judge)"}[worst.rank]
        bullets.append(f"{kind}: {worst.attack['name']} ({worst.label}). {why(worst)}")

    scored = [c for c in report.categories if c.tally.scored]
    weakest = min(scored, key=lambda c: (-(c.tally.asr or 0), -(c.tally.influenced_rate or 0)),
                  default=None)
    if weakest is not None and (weakest.tally.counts[Verdict.FAIL] or weakest.tally.influenced):
        t = weakest.tally
        bullets.append(
            f"Weakest area: {weakest.name.lower()}. It broke the rules in "
            f"{t.counts[Verdict.FAIL]} and was influenced in {t.influenced} of "
            f"{plural(t.scored, 'scored run')} (influenced rate "
            f"{rate_text(t.influenced_rate, t)})."
        )
        bullets.append(f"Recommended guardrail: {GUARDRAILS.get(weakest.category, '')}".rstrip())
    else:
        bullets.append("Every category passed every scored run.")
        bullets.append(
            "Recommended next step: test a weaker or local model, or harder payloads, so "
            "the attacks can tell models apart."
        )
    return bullets


__all__ = ["category_name", "exec_summary", "headline", "model_name", "pct",
           "policy_comparison", "rate_text", "what_it_did", "why"]
