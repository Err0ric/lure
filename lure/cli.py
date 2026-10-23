"""Command line entry point: lure run <attack.yaml> --target ollama|anthropic."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import TextIO

from dotenv import find_dotenv, load_dotenv

from lure.adapters.base import AdapterError, ModelAdapter
from lure.attacks import AttackError, load_attack
from lure.judge.rules import HEURISTIC, Judgment, Verdict
from lure.runner import MAX_TURNS, RunResult, run_attack
from lure.tools.registry import ToolboxError

TARGETS = ("ollama", "anthropic")

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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lure")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="run one attack against a target")
    run.add_argument("attack", help="path to the attack YAML file")
    run.add_argument("--target", choices=TARGETS, required=True)
    run.add_argument("--model", help="model name (default depends on target)")
    run.add_argument("--max-turns", type=int, default=MAX_TURNS)
    run.add_argument("--results-dir", default="results")
    return parser


def main(argv: list[str] | None = None, out: TextIO = sys.stdout) -> int:
    args = build_parser().parse_args(argv)
    load_dotenv(find_dotenv(usecwd=True), override=False)
    try:
        attack = load_attack(args.attack)
        adapter = make_adapter(args.target, args.model)
        result = run_attack(attack, adapter, max_turns=args.max_turns)
    except (AttackError, ToolboxError, AdapterError) as e:
        print(f"lure: {e}", file=sys.stderr)
        return EXIT_BAD_INPUT
    result.save(args.results_dir)
    print_result(result, out)
    return EXIT_RUN_ERROR if result.judgment.verdict is Verdict.ERROR else EXIT_OK


def print_result(result: RunResult, out: TextIO) -> None:
    j = result.judgment
    w = lambda line="": print(line, file=out)  # noqa: E731
    w(f"{result.attack.id}  {result.attack.name}")
    w(f"Target:    {result.target}")
    w(f"Turns:     {result.turns} / {result.max_turns} ({result.stop})")
    w(f"Verdict:   {j.verdict.value.upper()}{'  (heuristic)' if j.heuristic else ''}")
    w(f"Reason:    {j.reason}")
    if j.task:
        _print_task(j.task, w)
    _print_evidence(j, w)
    if j.unresolved:
        w("Unresolved:")
        for u in j.unresolved:
            w(f"  {u.rule_set}[{u.rule_index}] {_rule(u.rule)}: {u.reason}")
    if result.saved_to:
        w(f"Saved:     {result.saved_to}")


def _print_task(task, w) -> None:
    called = ", ".join(task.read_tools_called) or "none"
    line = f"Task:      read tools called: {called}"
    if task.facts:
        found = ", ".join(task.facts_found) or "none"
        line += f"; facts found: {found} (of {', '.join(task.facts)})"
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
