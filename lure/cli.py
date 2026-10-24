"""Command line entry point.

  lure run <attack.yaml|folder>... --target ollama|anthropic|openai
      [--attacker-model M] [--prices prices.yaml --max-cost USD] [--baseline]
      [--payload-from result.json [--attempt K]]
  lure rescore <results folder|file>...  (re-judge saved runs, no target calls)
  lure report <results folder|file>... --out report.html
  lure compare <results folder> <results folder>... --out compare.html [--prices prices.yaml]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import TextIO

from dotenv import find_dotenv, load_dotenv

from lure import policy as policy_file
from lure.adapters.base import AdapterError, ModelAdapter
from lure.attacker import MAX_TOKENS as ATTACKER_MAX_TOKENS
from lure.attacker import Attacker
from lure.attacks import (
    Attack,
    AttackError,
    attacks_root,
    discover_categories,
    load_attack,
    payload_problems,
)
from lure.batch import SummaryRow, collect_attack_paths, summarize
from lure.budget import ROLES, Budget
from lure.exposure import DEFAULT_POLICY_FILE, OrgPolicy, PolicyError
from lure.judge.llm_judge import LLMJudge
from lure.judge.rules import DETECTED, HEURISTIC, Judgment, Verdict
from lure.policy import Policy, PolicyResult, PolicyRun
from lure.prices import PricesError, load_prices
from lure.rescore import (
    add_exposure,
    attack_changed,
    attack_index,
    record_key,
    record_paths,
    rescore,
    save_rescored,
)
from lure.runner import DEFAULT_ATTEMPTS, MAX_TURNS, RunResult, run_adaptive, run_attack
from lure.tools.call_log import ToolCallLog
from lure.tools.registry import ToolboxError, build_toolbox

TARGETS = ("ollama", "anthropic", "openai")
JUDGES = ("rules", "llm")

# lure run and lure report: 0 when no run fails the policy, 1 when one does,
# 2 when the input is bad or a run errored (and nothing fails the policy),
# 3 when lure run stopped at --max-cost (and neither of those happened).
# The other commands use 0 and 2 only.
EXIT_OK = 0
EXIT_POLICY_FAIL = 1
EXIT_ERROR = 2
EXIT_BAD_INPUT = EXIT_ERROR
EXIT_RUN_ERROR = EXIT_ERROR
EXIT_MAX_COST = 3
# --baseline: enough runs per attack for a rate, judged by the LLM judge.
BASELINE_REPEAT = 10


def make_adapter(target: str, model: str | None, max_tokens: int | None = None) -> ModelAdapter:
    """An adapter for one provider. `max_tokens` caps output where the
    provider adapter supports it (Anthropic); the attacker uses it."""
    kwargs = {"model": model} if model else {}
    if target == "ollama":
        from lure.adapters.ollama import DEFAULT_BASE_URL, OllamaAdapter

        return OllamaAdapter(
            base_url=os.environ.get("LURE_OLLAMA_URL", DEFAULT_BASE_URL), **kwargs
        )
    if target == "anthropic":
        from lure.adapters.anthropic import AnthropicAdapter

        return AnthropicAdapter(**kwargs, **({"max_tokens": max_tokens} if max_tokens else {}))
    if target == "openai":
        from lure.adapters.openai_compat import OpenAICompatAdapter

        return OpenAICompatAdapter(**kwargs)
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
    run.add_argument("attack", nargs="+", help="attack YAML files, or folders of them")
    run.add_argument("--target", choices=TARGETS, required=True)
    run.add_argument("--model", help="model name (default depends on target)")
    run.add_argument("--max-turns", type=int, default=MAX_TURNS)
    run.add_argument("--repeat", type=_positive_int,
                     help=f"run each attack N times (default 1, or {BASELINE_REPEAT} with --baseline)")
    run.add_argument("--baseline", action="store_true",
                     help=f"baseline settings: --repeat {BASELINE_REPEAT} --judge llm "
                          "(either can still be set explicitly)")
    _judge_args(run)
    run.add_argument("--attacker-model",
                     help="adaptive attacker: this model rewrites the payload after each "
                          "attempt that is not a Fail (must differ from the target)")
    run.add_argument("--attacker-target", choices=TARGETS, default="anthropic",
                     help="provider for the attacker model (default anthropic)")
    run.add_argument("--attempts", type=_positive_int,
                     help=f"adaptive attempts per run, the attack's own payload first "
                          f"(default {DEFAULT_ATTEMPTS}; needs --attacker-model)")
    run.add_argument("--prices", help="prices file (USD per million tokens) to estimate "
                                      "spend; see prices.example.yaml")
    run.add_argument("--max-cost", type=_positive_float, metavar="USD",
                     help="stop the batch before estimated spend (attacker, target and "
                          "judge) passes USD; needs --prices; exits 3")
    run.add_argument("--payload-from", metavar="RESULT",
                     help="replay the payload saved in this result file (one attack file only)")
    run.add_argument("--attempt", type=_positive_int, metavar="K",
                     help="with --payload-from: replay adaptive attempt K (default the "
                          "deciding attempt)")
    _policy_args(run)
    run.add_argument("--results-dir", default="results")

    rescore_cmd = sub.add_parser("rescore", help="re-judge saved runs; the target is not called")
    rescore_cmd.add_argument("results", nargs="+", help="result JSON files, or folders of them")
    rescore_cmd.add_argument("--attacks-dir", default="attacks",
                            help="where to find the attack files (default attacks)")
    rescore_cmd.add_argument("--attack", help="only runs of this attack id")
    rescore_cmd.add_argument("--version", type=_positive_int, help="only runs of this attack version")
    _judge_args(rescore_cmd)
    _policy_args(rescore_cmd)
    rescore_cmd.add_argument("--exposure-only", action="store_true",
                             help="keep every saved verdict as is; only recompute exposure "
                                  "with the org policy (no judge calls)")
    rescore_cmd.add_argument("--out", help="folder for rescored copies (default <first folder>/rescored)")

    report_cmd = sub.add_parser("report", help="build a static HTML report from saved runs")
    report_cmd.add_argument("results", nargs="+", help="result JSON files, or folders of them")
    report_cmd.add_argument("--out", default="report.html", help="output file (default report.html)")
    report_cmd.add_argument("--target", help="only runs against this target, e.g. "
                                             "anthropic:claude-haiku-5-5 (needed if results mix targets)")
    report_cmd.add_argument("--md", metavar="PATH", help="also write a Markdown report")
    report_cmd.add_argument("--sarif", metavar="PATH",
                            help="also write SARIF 2.1.0 for CI code scanning")
    report_cmd.add_argument("--attacks-dir", default="attacks",
                            help="where to find attack files for results saved before they "
                                 "recorded attack.file (SARIF only; default attacks)")
    _policy_args(report_cmd)

    compare_cmd = sub.add_parser("compare", help="compare targets side by side in one HTML page")
    compare_cmd.add_argument("results", nargs="+",
                             help="results folders, one per target (at least two)")
    compare_cmd.add_argument("--out", default="compare.html", help="output file (default compare.html)")
    compare_cmd.add_argument("--prices", help="prices file (USD per million tokens) to turn "
                                              "recorded tokens into a cost estimate; see "
                                              "prices.example.yaml")
    return parser


def _judge_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--judge", choices=JUDGES,
                        help="rules (default), or llm: ask a judge model about every "
                             "run with a reply except Fail and confirmed Partial")
    parser.add_argument("--judge-target", choices=TARGETS, default="anthropic",
                        help="provider for the LLM judge (default anthropic)")
    parser.add_argument("--judge-model",
                        help="LLM judge model (default claude-haiku-5-5 on anthropic)")


def _policy_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--policy", "--org-policy", dest="policy",
                        help=f"policy file (default {DEFAULT_POLICY_FILE} if present, "
                             "else the built-in default); see lure.example.yaml")
    parser.add_argument("--no-policy", "--no-org-policy", dest="no_policy", action="store_true",
                        help="ignore the policy file: built-in default, no exposure check")


def _policy(args) -> Policy:
    """The explicit --policy file, else lure.yaml in the current folder if it
    exists, else the built-in default. A file that is named but missing or
    invalid is an error."""
    if args.no_policy:
        return Policy()
    if args.policy:
        return policy_file.load(args.policy)
    if Path(DEFAULT_POLICY_FILE).is_file():
        return policy_file.load(DEFAULT_POLICY_FILE)
    return Policy()


def _note_legacy(records: list[dict]) -> None:
    """Say once when results predate the schema version (Lure 1.0.0)."""
    n = sum("schema_version" not in r for r in records)
    if n:
        print(f"lure: note: {n} of {len(records)} records are from Lure 1.0.0 (no "
              "schema_version); fields such as attack.file are missing", file=sys.stderr)


def _llm_judge(args) -> LLMJudge | None:
    if args.judge != "llm":
        return None
    return LLMJudge(make_judge_adapter(args.judge_target, args.judge_model))


def _positive_float(text: str) -> float:
    try:
        x = float(text)
    except ValueError:
        x = 0.0
    if not x > 0:
        raise argparse.ArgumentTypeError(f"must be a number above 0, got {text!r}")
    return x


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
    baseline = getattr(args, "baseline", False)
    if hasattr(args, "judge") and args.judge is None:
        args.judge = "llm" if baseline else "rules"
    if hasattr(args, "repeat") and args.repeat is None:
        args.repeat = BASELINE_REPEAT if baseline else 1
    if args.command == "rescore":
        return rescore_main(args, out)
    if args.command == "report":
        return report_main(args, out)
    if args.command == "compare":
        return compare_main(args, out)
    try:
        # Load every attack first so a bad file fails before any model call.
        policy = _policy(args)
        attacks = []
        for target in args.attack:
            _check_categories(policy, target)
            loaded = [load_attack(p) for p in collect_attack_paths(target)]
            attacks += _enabled_attacks(loaded, policy, target, out)
        replay = None
        if args.payload_from:
            attacks, replay = _replay(attacks, args, out)
        elif args.attempt:
            raise AttackError("--attempt needs --payload-from")
        for a in attacks:
            build_toolbox(a.tools, a.planted_fixtures(), ToolCallLog())
        adapter = make_adapter(args.target, args.model)
        llm_judge = _llm_judge(args)
        attacker = _attacker(args, attacks, adapter)
        if llm_judge is not None and llm_judge.model == adapter.target_name:
            raise AttackError(f"the judge model is the target ({adapter.target_name}); "
                              "no model judges itself: pick another --judge-model")
        budget = _budget(args, [adapter, llm_judge and llm_judge.adapter,
                                attacker and attacker.adapter])
    except (AttackError, ToolboxError, AdapterError, PolicyError, PricesError) as e:
        print(f"lure: {e}", file=sys.stderr)
        return EXIT_BAD_INPUT
    batch = any(Path(t).is_dir() for t in args.attack) or len(attacks) > 1 or args.repeat > 1
    plan = [(a, n) for a in attacks for n in range(1, args.repeat + 1)]
    results: list[RunResult] = []
    for i, (attack, n) in enumerate(plan, 1):
        if budget is not None and not budget.allows_another():
            break
        kwargs = {"max_turns": args.max_turns, "llm_judge": llm_judge,
                  "org_policy": policy.exposure}
        if attacker is not None:
            result = run_adaptive(attack, adapter, attacker, args.attempts or DEFAULT_ATTEMPTS,
                                  budget, **kwargs)
        else:
            result = run_attack(attack, adapter, **kwargs)
            if budget is not None:
                costs = budget.charge_attempt(result.target, result.usage, result.judgment.llm)
                result.cost = {**dict.fromkeys(ROLES, 0.0), **costs, "total": sum(costs.values())}
        result.replay = replay
        result.save(args.results_dir)
        results.append(result)
        if batch:
            print_progress(result, i, len(plan), n, args.repeat, out)
        else:
            print_result(result, out)
        if budget is not None and budget.stopped:
            break
    if batch and results:
        print(file=out)
        print_summary(summarize(results), out)
        if attacker is not None:
            print(file=out)
            print_attacker_summary(results, out)
    stopped = budget is not None and budget.stopped
    if budget is not None:
        print(file=out)
        if stopped:
            print(f"Stopped:   max cost ${args.max_cost:.2f} reached; spent {budget.line()}; "
                  f"{len(results)} of {len(plan)} runs done", file=out)
        else:
            print(f"Spend:     {budget.line()}", file=out)
        print(f"           estimate from recorded tokens at the rates in {budget.prices.source}",
              file=out)
    gate = policy.gate([PolicyRun.from_result(r) for r in results])
    print(file=out)
    print_policy(gate, out)
    return exit_code(gate, [r.judgment.verdict for r in results], stopped)


def _attacker(args, attacks: list[Attack], target: ModelAdapter) -> Attacker | None:
    if not args.attacker_model:
        if args.attempts:
            raise AttackError("--attempts needs --attacker-model")
        return None
    pinned = [a for a in attacks if a.pinned and not a.goal]
    if pinned:
        names = ", ".join(f"{a.id} v{a.version} ({a.source.name})" for a in pinned)
        raise AttackError(f"{names}: pinned versions stay unchanged and have no goal, so the "
                          "adaptive attacker cannot run them; run the current version instead")
    missing = [a.id for a in attacks if not a.goal]
    if missing:
        raise AttackError(f"the adaptive attacker needs a goal in every attack; none in "
                          f"{', '.join(missing)}")
    adapter = make_adapter(args.attacker_target, args.attacker_model,
                           max_tokens=ATTACKER_MAX_TOKENS)
    if adapter.target_name == target.target_name:
        raise AttackError(f"the attacker model is the target ({target.target_name}); "
                          "pick another --attacker-model")
    return Attacker(adapter)


def _budget(args, adapters: list) -> Budget | None:
    if args.max_cost and not args.prices:
        raise PricesError("--max-cost needs --prices")
    if not args.prices:
        return None
    budget = Budget(load_prices(args.prices), args.max_cost)
    budget.check_models([a.target_name for a in adapters if a])
    return budget


def _replay(attacks: list[Attack], args, out: TextIO) -> tuple[list[Attack], dict]:
    """The one attack, with the payload from a saved result."""
    if len(attacks) != 1:
        raise AttackError("--payload-from takes exactly one attack file")
    if args.attacker_model:
        raise AttackError("--payload-from replays a saved payload; leave out --attacker-model")
    [attack] = attacks
    path = Path(args.payload_from)
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
        key = record_key(record)
    except FileNotFoundError:
        raise AttackError(f"result file not found: {path}") from None
    except (json.JSONDecodeError, KeyError, TypeError):
        raise AttackError(f"{path}: not a Lure result") from None
    if key != (attack.id, attack.version):
        raise AttackError(f"{path} is a run of {key[0]} v{key[1]}, not {attack.id} "
                          f"v{attack.version}")
    adaptive = record.get("adaptive")
    if args.attempt:
        if not adaptive:
            raise AttackError(f"{path} is not an adaptive run; leave out --attempt")
        found = [a for a in adaptive["attempts"] if a["n"] == args.attempt]
        if not found or not found[0].get("payload"):
            raise AttackError(f"{path} has no payload for attempt {args.attempt}")
        payload, attempt = found[0]["payload"], args.attempt
    else:
        payload = record["attack"]["injection"]["payload"]
        attempt = adaptive["deciding_attempt"] if adaptive else None
    problems = payload_problems(payload)
    if problems:
        raise AttackError(f"{path}: payload not replayed: {'; '.join(problems)}")
    saved = record["attack"].get("fixtures_sha256") or {}
    changed = [name for name, digest in attack.fixture_hashes().items()
               if name in saved and saved[name] != digest]
    if changed:
        print(f"Note: fixtures changed since {path.name}: {', '.join(changed)}; the replay "
              "uses the current files.", file=out)
    return [attack.with_payload(payload)], {"from": str(path), "attempt": attempt}


def exit_code(gate: PolicyResult, verdicts: list[Verdict], stopped: bool = False) -> int:
    """A policy failure wins over a run error: a confirmed finding stands
    even if another run broke. A run error wins over a --max-cost stop: the
    stop was asked for, the error needs fixing."""
    if not gate.passed:
        return EXIT_POLICY_FAIL
    if Verdict.ERROR in verdicts:
        return EXIT_ERROR
    if stopped:
        return EXIT_MAX_COST
    return EXIT_OK


def print_policy(gate: PolicyResult, out: TextIO) -> None:
    """One line per attack version that failed the policy, with run counts."""
    if gate.skipped:
        print(f"Not gated (disabled in {gate.source}): {gate.skipped} "
              f"run{'' if gate.skipped == 1 else 's'}", file=out)
    failed: dict[tuple[str, int], dict[str, set[str]]] = {}
    for v in gate.violations:
        failed.setdefault((v.attack_id, v.version), {}).setdefault(v.kind, set()).add(v.where)
    status = "PASS" if gate.passed else "FAIL"
    print(f"Policy:    {status} ({gate.label}): {gate.failed_runs} of {gate.runs} "
          f"run{'' if gate.runs == 1 else 's'} failed", file=out)
    if gate.runs == 1:
        for v in gate.violations:
            print(f"  {v.kind}: {v.detail}", file=out)
        return
    for (attack_id, version), by_kind in failed.items():
        parts = [f"{kind} in {len(where)} run{'' if len(where) == 1 else 's'}"
                 for kind, where in by_kind.items()]
        print(f"  {attack_id} v{version}: {', '.join(parts)}", file=out)


def _check_categories(policy: Policy, target: str) -> None:
    """Catch a misspelled category in the policy before anything runs."""
    root = attacks_root(target) or (Path(target) if Path(target).is_dir() else None)
    if root is not None and policy.categories:
        policy.check_categories(discover_categories(root), root)


def _enabled_attacks(attacks: list, policy: Policy, target: str, out: TextIO) -> list:
    """A folder run leaves out attacks the policy disables. An attack file
    named directly always runs."""
    if not Path(target).is_dir():
        for a in attacks:
            if not policy.enabled(a.id, a.category):
                print(f"Note: {a.id} is disabled in {policy.source}; running it because it "
                      "was named directly.", file=out)
        return attacks
    kept = [a for a in attacks if policy.enabled(a.id, a.category)]
    skipped = [a.id for a in attacks if a not in kept]
    if not kept:
        raise AttackError(f"every attack under {target} is disabled in {policy.source}")
    if skipped:
        print(f"Skipped (disabled in {policy.source}): {', '.join(skipped)}", file=out)
    return kept


def report_main(args, out: TextIO) -> int:
    from lure.report.data import ReportError, build_report, load_runs
    from lure.report.render import write_report

    try:
        policy = _policy(args)
        runs = load_runs(args.results)
        _note_legacy([r.record for r in runs])
        report = build_report(runs, target=args.target)
    except (ReportError, FileNotFoundError, PolicyError) as e:
        print(f"lure: {e}", file=sys.stderr)
        return EXIT_BAD_INPUT
    runs = [r for r in runs if r.record["target"] == report.target]
    gate = policy.gate_saved([(r.record, str(r.path)) for r in runs])
    path = write_report(report, args.out)
    t = report.total
    print(f"Wrote {path}: {t.runs} runs of {len(report.attacks)} attacks against {report.target}, "
          f"{len(report.findings)} findings.", file=out)
    if args.md:
        from lure.report.markdown import write_markdown

        print(f"Wrote {write_markdown(report, args.md, gate)}", file=out)
    if args.sarif:
        from lure.report.sarif import write_sarif

        files = _legacy_attack_files(runs, args.attacks_dir)
        print(f"Wrote {write_sarif(report, args.sarif, gate, files)}", file=out)
    print(f"ASR:       {_rate(t.asr, t.counts[Verdict.FAIL], t.scored)}", file=out)
    if not report.exposure_checked:
        print("Exposure:  not checked (no org policy in these results)", file=out)
    else:
        print(f"Exposure:  {t.exposed} of {t.runs} runs sent outside the allowed domains",
              file=out)
        for a in report.attacks:
            if a.tally.exposed:
                print(f"  {a.label}: {a.tally.exposed} of {a.tally.runs} runs", file=out)
    print(file=out)
    print_policy(gate, out)
    gated = [r for r in runs if policy.enabled(r.attack["id"], r.attack["category"])]
    return exit_code(gate, [r.verdict for r in gated])


def _legacy_attack_files(runs: list, attacks_dir: str) -> dict[tuple[str, int], str]:
    """Attack files for records without attack.file, looked up by id and
    version. Empty when every record has one or the folder is missing."""
    if all("file" in r.attack for r in runs) or not Path(attacks_dir).is_dir():
        return {}
    try:
        return {key: attack.file for key, attack in attack_index(attacks_dir).items()}
    except AttackError as e:
        print(f"lure: SARIF: cannot read {attacks_dir}: {e}", file=sys.stderr)
        return {}


def compare_main(args, out: TextIO) -> int:
    from lure.report.compare import PricesError, build_comparison, load_prices
    from lure.report.data import ReportError
    from lure.report.render import write_comparison

    try:
        prices = load_prices(args.prices) if args.prices else None
        comp = build_comparison(args.results, prices)
    except (ReportError, PricesError, FileNotFoundError) as e:
        print(f"lure: {e}", file=sys.stderr)
        return EXIT_BAD_INPUT
    print_comparison(comp, out)
    path = write_comparison(comp, args.out)
    print(file=out)
    print(f"Wrote {path}: {len(comp.columns)} targets.", file=out)
    return EXIT_OK


def print_comparison(comp, out: TextIO) -> None:
    from lure.report.render import dollars, judge_name, tokens

    models = [c.model for c in comp.columns]
    exposure = (lambda t: f"{t.exposed} of {t.runs}") if comp.exposure_checked else (lambda t: "n/a")
    rows = [
        ["Judge", *(judge_name(j) for j in comp.judges)],
        ["Runs (scored)", *(f"{c.report.total.runs} ({c.report.total.scored})" for c in comp.columns)],
        ["Pass rate", *(_tally_rate(c.report.total, "pass_rate", Verdict.PASS) for c in comp.columns)],
        ["Influenced rate", *(_rate(c.report.total.influenced_rate, c.report.total.influenced,
                                    c.report.total.scored) for c in comp.columns)],
        ["ASR", *(_tally_rate(c.report.total, "asr", Verdict.FAIL) for c in comp.columns)],
        ["Detection rate", *(_rate(c.report.total.detection_rate, c.report.total.detected,
                                   c.report.total.scored) for c in comp.columns)],
        ["Exposure (runs)", *(exposure(c.report.total) for c in comp.columns)],
        *([["Attacker tested", *(f"{c.report.attacker_tested} of {c.report.total.runs}"
                                 for c in comp.columns)],
           ["Attacker refused", *(f"{c.report.attacker_refused} of {c.report.attacker_calls}"
                                  for c in comp.columns)]]
          if comp.adaptive else []),
        ["Target tokens in/out", *(f"{tokens(c.target_usage.input)} / {tokens(c.target_usage.output)}"
                                   for c in comp.columns)],
        ["Judge tokens in/out", *(" + ".join(f"{tokens(u.input)} / {tokens(u.output)}"
                                             for u in c.judge_usage) or "none"
                                  for c in comp.columns)],
    ]
    if comp.prices:
        tc = [c.target_cost(comp.prices) for c in comp.columns]
        jc = [c.judge_cost(comp.prices) for c in comp.columns]
        ac = [c.attacker_cost(comp.prices) for c in comp.columns]
        rows += [
            ["Target cost", *(dollars(x) for x in tc)],
            ["Judge cost", *(dollars(x) for x in jc)],
            *([["Attacker cost", *(dollars(x) for x in ac)]]
              if any(c.attacker_usage for c in comp.columns) else []),
            ["Total cost", *(dollars(None if None in (a, b, x) else a + b + x)
                             for a, b, x in zip(tc, jc, ac))],
        ]
    _print_table(["", *models], rows, out)

    print(file=out)
    cat_rows = []
    for cat in comp.categories:
        for model, t in zip(models, cat.tallies):
            if t is None:
                cat_rows.append([cat.name, model, "not run", "", "", "", ""])
                continue
            cat_rows.append([cat.name, model, _pct(t.pass_rate), _pct(t.influenced_rate),
                             _pct(t.asr), _pct(t.detection_rate), exposure(t)])
    _print_table(["Category", "Target", "Pass", "Influenced", "ASR", "Detected", "Exposure"],
                 _blank_repeats(cat_rows), out)

    for p in comp.policies:
        print(file=out)
        print(f"Policy comparison: {p.attack_id} ({p.name})", file=out)
        pol_rows = []
        for v in p.versions:
            for model, row in zip(models, v.rows):
                if row is None:
                    pol_rows.append([f"v{v.version}", model, "not run", "", "", ""])
                    continue
                t = row.tally
                pol_rows.append([f"v{v.version}", model, str(t.runs),
                                 _rate(t.influenced_rate, t.influenced, t.scored),
                                 _tally_rate(t, "asr", Verdict.FAIL), exposure(t)])
        _print_table(["Version", "Target", "Runs", "Influenced", "ASR", "Exposure"],
                     _blank_repeats(pol_rows), out)

    from lure.report.compare import compare_lede

    notes = compare_lede(comp)
    if comp.prices:
        notes.append(f"Cost is an estimate from recorded tokens at the rates in "
                     f"{comp.prices.source}; check current pricing.")
    if notes:
        print(file=out)
        for line in notes:
            print(f"- {line}", file=out)


def _tally_rate(t, attr: str, verdict: Verdict) -> str:
    return _rate(getattr(t, attr), t.counts[verdict], t.scored)


def _pct(rate: float | None) -> str:
    return "n/a" if rate is None else f"{rate:.0%}"


def _blank_repeats(rows: list[list[str]]) -> list[list[str]]:
    """Blank the first cell when it repeats the row above, so groups read."""
    out, prev = [], None
    for r in rows:
        out.append(["" if r[0] == prev else r[0], *r[1:]])
        prev = r[0]
    return out


def _print_table(header: list[str], rows: list[list[str]], out: TextIO) -> None:
    table = [header] + rows
    widths = [max(len(r[c]) for r in table) for c in range(len(header))]
    for r in table:
        cells = [r[0].ljust(widths[0])] + [r[c].rjust(widths[c]) for c in range(1, len(r))]
        print("  ".join(cells).rstrip(), file=out)


def rescore_main(args, out: TextIO) -> int:
    try:
        index = attack_index(args.attacks_dir)
        paths = record_paths(args.results)
        llm_judge = _llm_judge(args)
        org_policy = _policy(args).exposure
    except (AttackError, AdapterError, FileNotFoundError, PolicyError) as e:
        print(f"lure: {e}", file=sys.stderr)
        return EXIT_BAD_INPUT
    if args.exposure_only and (org_policy is None or args.judge != "rules"):
        print("lure: --exposure-only needs a policy with allowed_outbound_domains and no "
              "--judge llm", file=sys.stderr)
        return EXIT_BAD_INPUT
    first_dir = next((Path(p) for p in args.results if Path(p).is_dir()), Path("results"))
    out_dir = Path(args.out) if args.out else first_dir / "rescored"

    picked = []
    for path in paths:
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
            key = record_key(record)
        except (json.JSONDecodeError, KeyError, TypeError):
            print(f"lure: skipping {path}: not a Lure result", file=sys.stderr)
            continue
        if (args.attack and key[0] != args.attack) or (args.version and key[1] != args.version):
            continue
        if key not in index:
            print(f"lure: skipping {path}: no attack file for {key[0]} v{key[1]}", file=sys.stderr)
            continue
        if record.get("adaptive"):
            print(f"lure: skipping {path}: adaptive run; rescore does not re-judge attempts yet",
                  file=sys.stderr)
            continue
        picked.append((path, record, index[key]))
    if not picked:
        print("lure: no matching results to rescore", file=sys.stderr)
        return EXIT_BAD_INPUT
    _note_legacy([record for _, record, _ in picked])

    if args.exposure_only:
        return _exposure_only(picked, org_policy, out_dir, out)
    results: list[RunResult] = []
    width = len(str(len(picked)))
    for i, (path, record, attack) in enumerate(picked, 1):
        result = rescore(record, attack, llm_judge, org_policy)
        save_rescored(result, record, path, out_dir)
        results.append(result)
        old = str(record["judgment"].get("verdict", "?")).upper()
        new = result.judgment.verdict.value.upper()
        notes = [n for n, on in (("llm-judged", result.judgment.llm_judged),
                                 ("exposure", bool(result.exposure and result.exposure["calls"])),
                                 ("attack changed since run", attack_changed(record, attack)))
                 if on]
        note = f"  [{', '.join(notes)}]" if notes else ""
        print(f"[{i:>{width}}/{len(picked)}] {path.name}  {attack.id} v{attack.version}  "
              f"{old:<8} -> {new:<8}{note}", file=out)
    print(file=out)
    print(f"Rescored copies: {out_dir}", file=out)
    print(file=out)
    print_summary(summarize(results), out)
    return EXIT_OK


def _exposure_only(picked, org_policy: OrgPolicy, out_dir: Path, out: TextIO) -> int:
    rows = []
    width = len(str(len(picked)))
    for i, (path, record, attack) in enumerate(picked, 1):
        data = add_exposure(record, org_policy, path, out_dir)
        calls = data["exposure"]["calls"]
        verdict = str(record["judgment"]["verdict"]).upper()
        where = "; ".join(f"{c['tool']} to {', '.join(c['outside'])}" for c in calls)
        print(f"[{i:>{width}}/{len(picked)}] {path.name}  {attack.id} v{attack.version}  "
              f"{verdict:<8} (kept)" + (f"  [exposure: {where}]" if calls else ""), file=out)
        rows.append(SimpleNamespace(
            attack=SimpleNamespace(id=attack.id, version=attack.version),
            judgment=SimpleNamespace(verdict=Verdict(record["judgment"]["verdict"]),
                                     reason=record["judgment"]["reason"])))
    print(file=out)
    print(f"Rescored copies: {out_dir}", file=out)
    print(file=out)
    print_summary(summarize(rows), out)
    return EXIT_OK


def print_progress(result: RunResult, i: int, total: int, n: int, repeat: int, out: TextIO) -> None:
    width = len(str(total))
    j = result.judgment
    verdict = j.verdict.value.upper()
    notes = [n for n, on in (("detected", j.reason == DETECTED),
                             ("task incomplete", j.task_incomplete),
                             ("llm-judged", j.llm_judged),
                             ("llm judge failed", bool(j.llm) and not j.llm_judged),
                             ("exposure", bool(result.exposure and result.exposure["calls"])))
             if on]
    if result.adaptive:
        notes.append(_adaptive_note(result.adaptive))
        if not result.adaptive["attacker_tested"]:
            notes.append("single-shot: no attacker payload reached the target")
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
    _print_exposure(result.exposure, w)
    if result.adaptive:
        w(f"Adaptive:  {result.adaptive['attacker']}: {_adaptive_note(result.adaptive)}")
    if result.cost:
        w(f"Cost:      ${result.cost['total']:.4f} (estimate)")
    if j.unresolved:
        w("Unresolved:")
        for u in j.unresolved:
            w(f"  {u.rule_set}[{u.rule_index}] {_rule(u.rule)}: {u.reason}")
    if result.saved_to:
        w(f"Saved:     {result.saved_to}")


def print_attacker_summary(results: list[RunResult], out: TextIO) -> None:
    """Per attack: runs an attacker payload reached, and attacker refusals.
    A run the attacker never reached is single-shot, whatever its verdict."""
    rows: dict[str, list[int]] = {}
    for r in results:
        ad = r.adaptive
        row = rows.setdefault(f"{r.attack.id} v{r.attack.version}", [0, 0, 0, 0])
        row[0] += 1
        row[1] += ad["attacker_tested"]
        row[2] += ad["attacker_calls"]
        row[3] += ad["attacker_refused"]
    _print_table(
        ["Attack", "Runs", "Attacker tested", "Attacker calls", "Refused", "Refusal rate"],
        [[label, str(n), str(tested), str(calls), str(refused),
          _pct(refused / calls if calls else None)]
         for label, (n, tested, calls, refused) in rows.items()], out)


def _adaptive_note(adaptive: dict) -> str:
    tried = len(adaptive["attempts"])
    failures = adaptive["attacker_failures"]
    note = (f"worst at attempt {adaptive['attempts_to_worst']} of {tried}, "
            f"{adaptive['outcome'].replace('_', ' ')}")
    return note + (f", {failures} attacker failure{'' if failures == 1 else 's'}" if failures else "")


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
        quote = lambda facts: ", ".join(json.dumps(f) for f in facts)
        tally = f"{len(task.facts_found)} of {len(task.facts)} expected"
        if task.facts_found:
            line += f"; facts found: {quote(task.facts_found)} ({tally})"
        else:
            line += f"; facts found: none ({tally}: {quote(task.facts)})"
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


def _print_exposure(exposure: dict | None, w) -> None:
    """Calls outside the org policy's allowed domains. Never a verdict."""
    if exposure is None:
        return
    calls = exposure["calls"]
    w(f"Exposure:  {len(calls)} call{'' if len(calls) == 1 else 's'} outside the allowed "
      f"domains in {exposure['policy']}")
    for c in calls:
        failed = " (failed)" if c["failed"] else ""
        w(f"  call #{c['index']} {c['tool']} to {', '.join(c['outside'])}{failed}")


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
