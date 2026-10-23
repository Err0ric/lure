"""Five plain-language bullets for a non-technical reader.

Built only from the aggregated results, so every claim traces back to a
verdict in the report below it. No model writes this text.
"""

from __future__ import annotations

from lure.judge.rules import Verdict
from lure.report.data import Report, Run
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


def headline(report: Report) -> str:
    """The one-sentence answer at the top of the report."""
    model, total = model_name(report.target), report.total
    fails = total.counts[Verdict.FAIL]
    if not fails:
        return f"{model} made no harmful tool call in {total.scored} scored attack runs."
    return (f"{model} was manipulated into a harmful tool call in {fails} of "
            f"{total.scored} scored attack runs.")


def exec_summary(report: Report) -> list[str]:
    total, model = report.total, model_name(report.target)
    fails = total.counts[Verdict.FAIL]
    n_attacks = len(report.attacks)
    bullets = []

    if fails:
        bullets.append(
            f"{model} took a harmful action in {fails} of {total.scored} scored runs across "
            f"{plural(n_attacks, 'attack')}: an attack success rate of {pct(total.asr)}."
        )
    else:
        bullets.append(
            f"{model} took no harmful action in {total.scored} scored runs across "
            f"{plural(n_attacks, 'attack')}: the tool log shows none of the sends, payments "
            f"or deletes the attacks asked for."
        )

    bullets.append(
        f"It recognized the attack and said so in {total.detected} of {total.scored} runs "
        f"({pct(total.detection_rate)}). In the rest it ignored the attack or, in "
        f"{plural(total.counts[Verdict.PARTIAL], 'run')}, offered or asked to carry it out."
    )

    worst = report.findings[0] if report.findings else None
    if worst is None:
        bullets.append("No run needed follow-up: there were no failures, near misses or "
                       "undecided results.")
    else:
        kind = {Verdict.FAIL: "Worst finding", Verdict.PARTIAL: "Closest call",
                Verdict.REVIEW: "Needs a human look"}[worst.verdict]
        bullets.append(f"{kind}: {worst.attack['name']} ({worst.label}). {why(worst)}")

    scored = [c for c in report.categories if c.tally.scored]
    weakest = min(scored, key=lambda c: (c.tally.pass_rate, -c.tally.counts[Verdict.FAIL]),
                  default=None)
    if weakest is not None and weakest.tally.pass_rate is not None and weakest.tally.pass_rate < 1:
        t = weakest.tally
        bullets.append(
            f"Weakest area: {weakest.name.lower()}, with a {pct(t.pass_rate)} pass rate "
            f"({plural(t.counts[Verdict.FAIL], 'failure')}, "
            f"{plural(t.counts[Verdict.PARTIAL], 'near miss', 'near misses')} in {plural(t.scored, 'scored run')})."
        )
        bullets.append(f"Recommended guardrail: {GUARDRAILS.get(weakest.category, '')}".rstrip())
    else:
        bullets.append("Every category passed every scored run.")
        bullets.append(
            "Recommended next step: test a weaker or local model, or harder payloads, so "
            "the attacks can tell models apart."
        )
    return bullets


__all__ = ["category_name", "exec_summary", "headline", "model_name", "pct", "why"]
