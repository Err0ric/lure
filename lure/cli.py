"""Command line entry point: lure run <attack.yaml|folder> --target ollama|anthropic."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import TextIO

from dotenv import find_dotenv, load_dotenv

from lure.adapters.base import AdapterError, ModelAdapter
from lure.attacks import AttackError, load_attack
from lure.batch import SummaryRow, collect_attack_paths, summarize
from lure.judge.llm_judge import LLMJudge
from lure.judge.rules import DETECTED, HEURISTIC, Judgment, Verdict
from lure.runner import MAX_TURNS, RunResult, run_attack
from lure.tools.call_log import ToolCallLog
from lure.tools.registry import ToolboxError, build_toolbox

TARGETS = ("ollama", "anthropic")
JUDGES = ("rules", "llm")

EXIT_OK = 0
EXIT_RUN_ERROR = 1
EXIT_BAD_INPUT = 2


def make_adapter(target: str, model: str | None) -> ModelAdapter:
    kwargs = {"model": model} if model else {}
    if target == "ollama":
        from lure.adapters.ollama import DEFAULT_BASE_URL, OllamaAdapter

        return OllamaAdapter(
            base_url=os.environ.get("LURE_OLLAMA_URL", DEFAULT_BASE_URL), **kwargs
        )
    if target == "anthropic":
        from lure.adapters.anthropic import AnthropicAdapter

        return AnthropicAdapter(**kwargs)
    raise ValueError(f"unknown target {target!r}")


def make_judge_adapter(target: str, model: str | None) -> ModelAdapter:
    """The judge model's own adapter, separate from the target's."""
    from lure.judge.llm_judge import DEFAULT_JUDGE_MODEL

    if target == "anthropic" and not model:
        model = DEFAULT_JUDGE_MODEL
    return make_adapter(target, model)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lure")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="run attacks against a target")
    run.add_argument("attack", help="attack YAML file, or a folder of them")
    run.add_argument("--target", choices=TARGETS, required=True)
    run.add_argument("--model", help="model name (default depends on target)")
    run.add_argument("--max-turns", type=int, default=MAX_TURNS)
    run.add_argument("--repeat", type=_positive_int, default=1,
                     help="run each attack N times (default 1)")
    run.add_argument("--judge", choices=JUDGES, default="rules",
                     help="rules (default), or llm: ask a judge model about every "
                          "run with a reply except Fail and confirmed Partial")
    run.add_argument("--judge-target", choices=TARGETS, default="anthropic",
                     help="provider for the LLM judge (default anthropic)")
    run.add_argument("--judge-model",
                     help="LLM judge model (default claude-haiku-5-5 on anthropic)")
    run.add_argument("--results-dir", default="results")
    return parser


def _positive_int(text: str) -> int:
    try:
        n = int(text)
    except ValueError:
        n = 0
    if n < 1:
        raise argparse.ArgumentTypeError(f"must be a whole number of at least 1, got {text!r}")
    return n


def main(argv: list[str] | None = None, out: TextIO = sys.stdout) -> int:
    args = build_parser().parse_args(argv)
    load_dotenv(find_dotenv(usecwd=True), override=False)
    try:
        # Load every attack first so a bad file fails before any model call.
        paths = collect_attack_paths(args.attack)
        attacks = [load_attack(p) for p in paths]
        for a in attacks:
            build_toolbox(a.tools, a.planted_fixtures(), ToolCallLog())
        adapter = make_adapter(args.target, args.model)
        llm_judge = None
        if args.judge == "llm":
            llm_judge = LLMJudge(make_judge_adapter(args.judge_target, args.judge_model))
    except (AttackError, ToolboxError, AdapterError) as e:
        print(f"lure: {e}", file=sys.stderr)
        return EXIT_BAD_INPUT
    batch = Path(args.attack).is_dir() or args.repeat > 1
    plan = [(a, n) for a in attacks for n in range(1, args.repeat + 1)]
    results: list[RunResult] = []
    for i, (attack, n) in enumerate(plan, 1):
        result = run_attack(attack, adapter, max_turns=args.max_turns, llm_judge=llm_judge)
        result.save(args.results_dir)
        results.append(result)
        if batch:
            print_progress(result, i, len(plan), n, args.repeat, out)
        else:
            print_result(result, out)
    if batch:
        print(file=out)
        print_summary(summarize(results), out)
    if any(r.judgment.verdict is Verdict.ERROR for r in results):
        return EXIT_RUN_ERROR
    return EXIT_OK


def print_progress(result: RunResult, i: int, total: int, n: int, repeat: int, out: TextIO) -> None:
    width = len(str(total))
    j = result.judgment
    verdict = j.verdict.value.upper()
    notes = [n for n, on in (("detected", j.reason == DETECTED),
                             ("task incomplete", j.task_incomplete),
                             ("llm-judged", j.llm_judged),
                             ("llm judge failed", bool(j.llm) and not j.llm_judged)) if on]
    note = f"  [{', '.join(notes)}]" if notes else ""
    print(f"[{i:>{width}}/{total}] {result.attack.id}  run {n}/{repeat}  "
          f"{verdict:<8}  {result.saved_to}{note}", file=out)


SUMMARY_VERDICTS = (
    Verdict.PASS, Verdict.PARTIAL, Verdict.REVIEW,
    Verdict.INVALID, Verdict.FAIL, Verdict.ERROR,
)


def print_summary(rows: list[SummaryRow], out: TextIO) -> None:
    header = ["Attack", "Runs", "Scored", *(v.value for v in SUMMARY_VERDICTS),
              "Pass rate", "ASR"]
    table = [header] + [
        [
            row.label,
            str(row.runs),
            str(row.scored),
            *(str(row.counts[v]) for v in SUMMARY_VERDICTS),
            _rate(row.pass_rate, row.counts[Verdict.PASS], row.scored),
            _rate(row.asr, row.counts[Verdict.FAIL], row.scored),
        ]
        for row in rows
    ]
    widths = [max(len(r[c]) for r in table) for c in range(len(header))]
    for r in table:
        cells = [r[0].ljust(widths[0])] + [r[c].rjust(widths[c]) for c in range(1, len(r))]
        print("  ".join(cells).rstrip(), file=out)
    unscored = [(row.label, key, n) for row in rows
                for key, n in row.unscored_reasons.items()]
    if unscored:
        print(file=out)
        print("Not scored (left out of Pass rate and ASR):", file=out)
        id_width = max(len(a) for a, _, _ in unscored)
        for attack_id, (verdict, reason), n in unscored:
            print(f"  {attack_id:<{id_width}}  {n}x {verdict.value.upper():<7}  {reason}",
                  file=out)


def _rate(rate: float | None, hits: int, scored: int) -> str:
    return "n/a" if rate is None else f"{rate:.0%} ({hits}/{scored})"


def print_result(result: RunResult, out: TextIO) -> None:
    j = result.judgment
    w = lambda line="": print(line, file=out)
    w(f"{result.attack.id}  {result.attack.name}")
    w(f"Target:    {result.target}")
    w(f"Turns:     {result.turns} / {result.max_turns} ({result.stop})")
    w(f"Verdict:   {j.verdict.value.upper()}{_verdict_note(j)}")
    w(f"Reason:    {j.reason}")
    if j.llm:
        _print_llm(j, w)
    if j.task_incomplete:
        w(f"Note:      task incomplete: {'. '.join(j.task.problems)}")
    if j.task:
        _print_task(j.task, w)
    _print_evidence(j, w)
    if j.unresolved:
        w("Unresolved:")
        for u in j.unresolved:
            w(f"  {u.rule_set}[{u.rule_index}] {_rule(u.rule)}: {u.reason}")
    if result.saved_to:
        w(f"Saved:     {result.saved_to}")


def _verdict_note(j: Judgment) -> str:
    if j.llm_judged:
        return "  (llm-judged)"
    return "  (heuristic)" if j.heuristic else ""


def _print_llm(j: Judgment, w) -> None:
    llm = j.llm
    if "error" in llm:
        w(f"LLM judge: {llm['model']} failed, rules verdict kept: {llm['error']}")
        return
    w(f"LLM judge: {llm['model']}: {llm['label']} (rules said {llm['rules']['verdict'].upper()})")
    quote = "" if llm["quote_found"] else "  [quote not found in reply]"
    w(f"           {llm['justification']}{quote}")


def _print_task(task, w) -> None:
    called = ", ".join(task.read_tools_called) or "none"
    line = f"Task:      read tools called: {called}"
    if task.facts:
        found = ", ".join(task.facts_found) or "none"
        line += f"; facts found: {found} (of {', '.join(task.facts)})"
    if task.actions_required:
        done = ", ".join(task.actions_done) or "none"
        line += f"; required actions done: {done} (of {', '.join(task.actions_required)})"
    w(line)


def _print_evidence(j: Judgment, w) -> None:
    if not j.evidence:
        return
    w("Evidence:")
    for e in j.evidence:
        w(f"  [{e.kind}] {e.rule_set}[{e.rule_index}] {_rule(e.rule)}")
        for c in e.calls:
            w(f"      call #{c['index']} {c['tool']}({_args(c['args'])})")
        if e.kind == HEURISTIC:
            for t in e.text:
                w(f"      text: {t!r}")


def _rule(rule: dict) -> str:
    return json.dumps(rule)


def _args(args: dict) -> str:
    parts = []
    for k, v in args.items():
        text = json.dumps(v)
        parts.append(f"{k}={text if len(text) <= 60 else text[:57] + '...'}")
    return ", ".join(parts)


if __name__ == "__main__":
    sys.exit(main())
