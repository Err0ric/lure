"""Re-judge saved runs with the current rules and judge, without the target.

A saved result holds the tool-call log and final reply, which is all the
Judge reads, so a run can be scored again after a rule or rubric change.
The original files are never changed; rescored copies are written to a
separate folder with the previous verdict recorded.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from lure.attacks import Attack, AttackError, load_attack
from lure.exposure import OrgPolicy
from lure.judge.llm_judge import LLMJudge
from lure.judge.rules import apply_refusal, judge, target_refused
from lure.runner import RunResult, judge_text
from lure.tools.call_log import ToolCall, ToolCallLog

# A profile run's summary (lure run --profile), next to its records.
MANIFEST = "manifest.json"
# Written by lure retest next to a run's records; not a run record either.
RETEST = "retest.json"


def attack_index(attacks_dir: str | Path) -> dict[tuple[str, int], Attack]:
    """Every attack under the folder, pinned versions included, by (id, version)."""
    index: dict[tuple[str, int], Attack] = {}
    for path in sorted(Path(attacks_dir).rglob("*.yaml")):
        attack = load_attack(path)
        key = (attack.id, attack.version)
        if key in index:
            raise AttackError(f"{attack.id} v{attack.version} is defined twice: "
                              f"{index[key].source} and {path}")
        index[key] = attack
    return index


def record_paths(paths: list[str | Path]) -> list[Path]:
    """Result files: each file given, plus *.json directly in each folder
    (not subfolders, so earlier rescored copies are not picked up)."""
    found: list[Path] = []
    for p in map(Path, paths):
        if p.is_dir():
            found += sorted(f for f in p.glob("*.json")
                            if f.is_file() and f.name not in (MANIFEST, RETEST))
        elif p.is_file():
            found.append(p)
        else:
            raise FileNotFoundError(f"results not found: {p}")
    return found


def record_key(record: dict[str, Any]) -> tuple[str, int]:
    # Results saved before attack versioning have no version: they are v1.
    attack = record["attack"]
    return attack["id"], attack.get("version", 1)


def rescore(record: dict[str, Any], attack: Attack, llm_judge: LLMJudge | None = None,
            org_policy: OrgPolicy | None = None) -> RunResult:
    """Judge a saved run again. Nothing is sent to the target model."""
    calls = record.get("tool_calls", [])
    stamps = iter(datetime.fromisoformat(c["timestamp"]) for c in calls)
    log = ToolCallLog(clock=lambda: next(stamps))
    for c in calls:
        log.record(c["tool"], c["args"], c.get("result"), c.get("alias"))
    final_text, error = record.get("final_text"), record.get("error")
    profile = record.get("profile")
    if profile is not None:
        # Judge it as the profiled agent met it: its own tool names count.
        from lure.profiles import with_alias_names
        attack = with_alias_names(attack, profile.get("tools", {}))
    # Records before schema v2 have no replies; their attacks were single-turn.
    replies = record.get("replies", [])
    text = judge_text(attack, final_text, replies)
    events = record.get("events", [])
    judgment = judge(attack, log, final_text=text, error=error, events=events)
    if target_refused(record.get("transcript", [])):
        judgment = apply_refusal(judgment)
    if llm_judge is not None:
        judgment = llm_judge.review(attack, judgment, text)
    if profile is not None:
        from lure.profiles import mark_setup_blocked
        judgment = mark_setup_blocked(judgment)
    return RunResult(
        attack=attack,
        target=record["target"],
        started_at=datetime.fromisoformat(record["started_at"]),
        finished_at=datetime.fromisoformat(record["finished_at"]),
        turns=record["turns"],
        max_turns=record["max_turns"],
        stop=record["stop"],
        final_text=final_text,
        transcript=record.get("transcript", []),
        log=log,
        judgment=judgment,
        error=error,
        judge=llm_judge.model if llm_judge is not None else "rules",
        # The target was not called again; keep the original run's usage.
        usage=record.get("usage", {}),
        exposure=(org_policy.record(log.calls, attack.expected_fetch,
                                    replies or [record.get("final_text")])
                  if org_policy is not None else record.get("exposure")),
        replies=replies,
        events=events,
        # What the original run cost: rescoring calls no target, and a judge
        # call it makes is in judgment.llm_judge.usage.
        cost=record.get("cost"),
        fixtures_sha256=record["attack"].get("fixtures_sha256", {}),
        profile=profile,
    )


def record_replies(record: dict[str, Any]) -> list[str | None]:
    """The agent's reply for each turn. Records before schema v2 have no
    replies; their attacks were single-turn, so the final text is the one."""
    return list(record.get("replies") or [record.get("final_text")])


def rebuild_calls(record: dict[str, Any]) -> list[ToolCall]:
    return [ToolCall(datetime.fromisoformat(c["timestamp"]), c["tool"], c["args"], c.get("result"),
                     c.get("alias"), c.get("gate")) for c in record.get("tool_calls", [])]


def add_exposure(record: dict[str, Any], org_policy: OrgPolicy, source: Path, out_dir: Path,
                 now: datetime | None = None,
                 expected_fetch: tuple[str, ...] = ()) -> dict[str, Any]:
    """Save a copy of the record with exposure recomputed and every other
    field, the judgment included, exactly as saved. expected_fetch comes
    from the attack file now, for records saved before attacks had it. For
    an adaptive run the record's calls and replies are the deciding
    attempt's, so its exposure is recomputed; the attempts keep theirs as
    saved (they record none)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    data = dict(record)
    expected = tuple(record["attack"].get("expected_fetch") or expected_fetch)
    if expected:
        data["attack"] = {**record["attack"], "expected_fetch": list(expected)}
    data["exposure"] = org_policy.record(rebuild_calls(record), expected, record_replies(record))
    data["rescore"] = {
        "source": str(source),
        "rescored_at": (now or datetime.now(UTC)).isoformat(),
        "exposure_only": True,
        "previous": {k: record["judgment"].get(k) for k in ("verdict", "reason")},
    }
    (out_dir / source.name).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return data


def attack_changed(record: dict[str, Any], attack: Attack) -> bool:
    """True if the payload in the saved run differs from the attack file now."""
    saved = record["attack"].get("injection", {}).get("payload")
    return saved is not None and saved != attack.injection.payload


def save_rescored(result: RunResult, record: dict[str, Any], source: Path, out_dir: Path,
                  now: datetime | None = None) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    data = result.to_dict()
    data["rescore"] = {
        "source": str(source),
        "rescored_at": (now or datetime.now(UTC)).isoformat(),
        "previous": {k: record["judgment"].get(k) for k in ("verdict", "reason")},
    }
    path = out_dir / source.name
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    result.saved_to = path
    return path
