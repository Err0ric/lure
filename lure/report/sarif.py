"""Render the report as SARIF 2.1.0, for CI code scanning (e.g. GitHub).

Lure finds weaknesses in an agent, not in code, so locations never point at
code. Each rule is an attack, its id the attack id, and each result points
at that attack's YAML file with no line region: the file that defines what
was tested. One result per attack version with a finding (Fail, Partial or
Review) or exposure; attacks with neither have a rule and no result, so a
fixed finding closes.

Reasons quote the target's reply, which is attack text by design. SARIF
message text supports [text](n) links, so brackets are escaped.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, TextIO

from lure import __version__
from lure.judge.rules import CONFIRM_FIRST, Verdict
from lure.policy import PolicyResult
from lure.report.data import FINDING_VERDICTS, Report, Run
from lure.report.exec_summary import pct, why
from lure.report.techniques import atlas_name, category_name

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/Err0ric/lure"
# GitHub reads security-severity as a CVSS-like score: 9.0+ critical,
# 7.0 to 8.9 high, 4.0 to 6.9 medium, below 4.0 low.
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0"}
RULE_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
MAX_TEXT = 1000


def message(value: object, limit: int = MAX_TEXT) -> str:
    """Untrusted text for a SARIF message: one line, brackets escaped."""
    line = " ".join(str(value).split())
    if len(line) > limit:
        line = line[: limit - 1].rstrip() + "…"
    return line.replace("\\", "\\\\").replace("[", "\\[").replace("]", "\\]")


def render_sarif(report: Report, gate: PolicyResult | None = None,
                 attack_files: dict[tuple[str, int], str] | None = None,
                 warn: TextIO = sys.stderr) -> dict[str, Any]:
    """The SARIF log. `attack_files` maps (id, version) to the attack file for
    records saved before attack.file was recorded."""
    by_key: dict[tuple[str, int], list[Run]] = {}
    for run in sorted(report.runs, key=lambda r: (r.key, r.started_at)):
        by_key.setdefault(run.key, []).append(run)
    exposed = {str(r.path) for r in report.exposed_runs}
    if gate is not None:
        exposed |= {v.where for v in gate.violations if v.kind == "exposure"}

    rules: dict[str, dict[str, Any]] = {}
    results = []
    for key, runs in by_key.items():
        attack = runs[-1].attack
        rules.setdefault(attack["id"], _rule(attack))
        result = _result(key, runs, exposed, report.target, attack_files or {}, warn)
        if result is not None:
            results.append(result)

    run: dict[str, Any] = {
        "tool": {"driver": {
            "name": "Lure",
            "version": __version__,
            "informationUri": INFORMATION_URI,
            "rules": list(rules.values()),
        }},
        "automationDetails": {"id": f"lure/{report.target}/"},
        "results": results,
        "properties": {"target": report.target, "runs": report.total.runs,
                       "scored": report.total.scored},
    }
    if gate is not None:
        run["properties"]["policy"] = {"source": gate.source, "path": gate.path,
                                       "sha256": gate.sha256, "passed": gate.passed,
                                       "failedRuns": gate.failed_runs, "runs": gate.runs}
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}


def _rule(attack: dict[str, Any]) -> dict[str, Any]:
    atlas = [f"{t} {atlas_name(t)}" if atlas_name(t) != t else t for t in attack["atlas"]]
    severity = attack.get("severity", "medium")
    help_text = (f"{category_name(attack['category'])} attack. ATLAS: {', '.join(atlas)}. "
                 f"ATT&CK: {', '.join(attack.get('attack') or []) or 'none'}. "
                 f"See the attack file for the scenario and the rules that score it.")
    return {
        "id": attack["id"],
        "name": attack["id"].replace("-", "_"),
        "shortDescription": {"text": message(attack["name"])},
        "fullDescription": {"text": message(attack["name"])},
        "help": {"text": help_text},
        "defaultConfiguration": {"level": RULE_LEVEL.get(severity, "warning")},
        "properties": {
            "tags": ["security", "ai-agent", attack["category"], *attack["atlas"],
                     *(attack.get("attack") or [])],
            "security-severity": SECURITY_SEVERITY.get(severity, "5.5"),
            "precision": "high",
            "severity": severity,
            "category": attack["category"],
            "atlas": attack["atlas"],
            "attack": attack.get("attack") or [],
        },
    }


def _result(key: tuple[str, int], runs: list[Run], exposed: set[str], target: str,
            attack_files: dict[tuple[str, int], str], warn: TextIO) -> dict[str, Any] | None:
    attack_id, version = key
    counts = {v: sum(r.verdict is v for r in runs) for v in Verdict}
    found = [r for r in runs if r.verdict in FINDING_VERDICTS and r.rank < 9]
    exposed_runs = [r for r in runs if str(r.path) in exposed]
    if not found and not exposed_runs:
        return None
    uri = runs[-1].attack.get("file") or attack_files.get(key)
    if uri is None:
        print(f"lure: SARIF: no attack file for {attack_id} v{version} (saved by Lure 1.0.0; "
              "pass --attacks-dir); its result is left out", file=warn)
        return None

    scored = len(runs) - counts[Verdict.INVALID] - counts[Verdict.ERROR]
    confirm = sum(r.partial_kind == CONFIRM_FIRST for r in runs)
    parts = [f"{v.value} in {counts[v]}"
             + (f" ({confirm} confirm first)" if v is Verdict.PARTIAL and confirm else "")
             for v in FINDING_VERDICTS if counts[v]]
    text = f"{attack_id} v{version} against {target}: "
    text += (", ".join(parts) + f" of {scored} scored runs") if parts else "no Fail, Partial or Review"
    if scored:
        text += f" (ASR {pct(counts[Verdict.FAIL] / scored)})"
    text += "."
    if exposed_runs:
        text += (f" {len(exposed_runs)} of {len(runs)} runs sent email or made a request "
                 "outside the allowed domains.")
    worst = min(found, key=lambda r: r.rank) if found else None
    if worst is not None:
        text += f" Worst run: {why(worst)}"
    if counts[Verdict.FAIL] or exposed_runs:
        level = "error"
    elif counts[Verdict.PARTIAL]:
        level = "warning"
    else:
        level = "note"
    return {
        "ruleId": attack_id,
        "level": level,
        "message": {"text": message(text)},
        "locations": [{"physicalLocation": {"artifactLocation": _artifact(uri)}}],
        "partialFingerprints": {"lureFinding/v1": f"{attack_id}:v{version}:{target}"},
        "properties": {
            "attackVersion": version,
            "runs": len(runs),
            "scored": scored,
            "verdicts": {v.value: n for v, n in counts.items() if n},
            **_partial_kinds(runs),
            "exposedRuns": len(exposed_runs),
            "resultFiles": [r.path.name for r in runs],
        },
    }


def _partial_kinds(runs: list[Run]) -> dict[str, Any]:
    """Partial runs by kind, when any recorded one (Lure 1.2 and later)."""
    kinds = Counter(r.partial_kind for r in runs if r.partial_kind)
    return {"partialKinds": dict(sorted(kinds.items()))} if kinds else {}


def _artifact(uri: str) -> dict[str, str]:
    """A path relative to the repo root, or a file URI when the attack was
    run from outside an attacks/ folder."""
    if uri.startswith("/"):
        return {"uri": Path(uri).as_uri()}
    return {"uri": uri, "uriBaseId": "%SRCROOT%"}


def write_sarif(report: Report, out: str | Path, gate: PolicyResult | None = None,
                attack_files: dict[tuple[str, int], str] | None = None,
                warn: TextIO = sys.stderr) -> Path:
    path = Path(out)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = render_sarif(report, gate, attack_files, warn)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return path
