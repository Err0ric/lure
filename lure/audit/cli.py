"""lure audit <profile>, and the pre-flight run before every profile run.

  lure audit PROFILE [--json FILE] [--sarif FILE] [--approval FILE]

Exit codes: 0 no critical finding, 1 a critical finding (a profile run
would stop here), 2 bad input.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, TextIO

from lure.audit.checks import audit
from lure.audit.findings import CHECKS, CRITICAL, INFO, OWASP, SEVERITIES, AuditResult
from lure.exposure import PolicyError
from lure.profiles import Profile, ProfileError, load_profile

AUDIT_FILE = "audit.json"
EXIT_OK, EXIT_BLOCKED, EXIT_BAD_INPUT = 0, 1, 2


def add_parser(sub) -> None:
    p = sub.add_parser("audit", help="check an agent's setup before any model call: "
                                     "credentials, auto-approve modes, ungated tools, egress, "
                                     "model endpoint, MCP servers (docs/audit.md)")
    p.add_argument("profile", help="the profile YAML to audit")
    p.add_argument("--policy", "--org-policy", dest="policy",
                   help="policy file (default lure.yaml if present)")
    p.add_argument("--no-policy", dest="no_policy", action="store_true")
    p.add_argument("--json", metavar="FILE", help="also write the findings as JSON")
    p.add_argument("--sarif", metavar="FILE", help="also write SARIF 2.1.0")
    p.add_argument("--approval", metavar="FILE",
                   help="also write a configuration-only approval page (HTML)")


def audit_main(args, out: TextIO = sys.stdout) -> int:
    from lure.cli import _policy
    try:
        profile = load_profile(args.profile)
        if args.policy is None and not args.no_policy and profile.policy is not None:
            args.policy = str(profile.policy)
        policy = _policy(args)
        result = audit(profile, policy)
    except (ProfileError, PolicyError, OSError) as e:
        print(f"lure: {e}", file=sys.stderr)
        return EXIT_BAD_INPUT
    print_audit(result, out)
    if args.json:
        print(f"Wrote {write_audit(result, args.json)}", file=out)
    if args.sarif:
        print(f"Wrote {write_sarif(result, args.sarif)}", file=out)
    if args.approval:
        from lure.report.approval import build_config_approval, write_approval
        page = build_config_approval(profile, result.to_dict(), policy)
        print(f"Wrote {write_approval(page, args.approval)}: {page.headline}", file=out)
    return EXIT_BLOCKED if result.blocked else EXIT_OK


def preflight(profile: Profile, policy, results_dir: str | Path, out: TextIO) -> AuditResult:
    """The audit before a profile run's first model call. Prints a short
    summary, and on a critical finding the findings and audit.json."""
    result = audit(profile, policy)
    c = result.counts()
    print(f"Audit:     {c[CRITICAL]} critical, {c['high'] + c['medium']} to review, "
          f"{c[INFO]} info ({result.scanner}); lure audit {profile.path} for details",
          file=out)
    if result.blocked:
        print_audit(result, out, only=(CRITICAL,))
        path = write_audit(result, Path(results_dir) / AUDIT_FILE)
        print(f"Stopped:   critical configuration findings; no model was called. Fix them and "
              f"rerun. Findings: {path}", file=out)
    return result


def print_audit(result: AuditResult, out: TextIO, only: tuple[str, ...] = SEVERITIES) -> None:
    if only == SEVERITIES:
        print(f"Audit:     {result.profile} ({result.scanner})", file=out)
    for f in result.to_dict()["findings"]:
        if f["severity"] not in only:
            continue
        print(f"  [{f['severity']}] {f['title']}: {f['what']}", file=out)
        print(f"      at:  {f['location']}"
              + (f" (fingerprint {f['fingerprint']})" if f.get("fingerprint") else ""), file=out)
        print(f"      fix: {f['fix']}", file=out)
    if only == SEVERITIES:
        c = result.counts()
        print(f"Summary:   {c[CRITICAL]} critical, {c['high']} high, {c['medium']} medium, "
              f"{c[INFO]} info" + ("; a profile run stops here" if result.blocked else ""),
              file=out)


def write_audit(result: AuditResult, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result.to_dict(), indent=2) + "\n", encoding="utf-8")
    return path


SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "info": "note"}


def sarif(result: AuditResult) -> dict[str, Any]:
    from lure import __version__
    rules = [{"id": f"lure-audit-{c.number:02d}-{c.key}", "name": c.key,
              "shortDescription": {"text": c.title},
              "properties": {"tags": [*c.atlas, *c.attack, *(f"{o} {OWASP[o]}" for o in c.owasp)],
                             "severity": c.severity}}
             for c in sorted(CHECKS.values(), key=lambda c: c.number)]
    index = {r["name"]: i for i, r in enumerate(rules)}
    results = []
    for f in result.to_dict()["findings"]:
        results.append({
            "ruleId": f"lure-audit-{f['check']:02d}-{f['key']}", "ruleIndex": index[f["key"]],
            "level": SARIF_LEVEL[f["severity"]],
            "message": {"text": f"{f['what']}. Fix: {f['fix']}"},
            "locations": [{"physicalLocation": {"artifactLocation": {
                "uri": f["location"].split(",")[0].split(": ")[0]}}}],
            **({"partialFingerprints": {"lureAudit/v1": f["fingerprint"]}}
               if f.get("fingerprint") else {}),
        })
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "lure audit", "version": __version__,
                                          "rules": rules}},
                      "results": results}]}


def write_sarif(result: AuditResult, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(sarif(result), indent=2) + "\n", encoding="utf-8")
    return path
