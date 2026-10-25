"""Find hardcoded credentials in text, without ever keeping one.

gitleaks is used when it is installed (`gitleaks stdin`, redacted): it
reports the rule and where, and Lure reads the value from its own copy of
the text only to fingerprint it. Otherwise, and as well, Lure's own
patterns: known key shapes, private keys, a secret-named setting with a
credential-shaped value, and Authorization headers. LURE-FAKE- canaries
and references to a variable (${API_KEY}, $TOKEN, env:...) are not
credentials. What comes back is a rule name, a line and a fingerprint.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass

from lure.attacks import FAKE_SECRET_PREFIX, PRIVATE_KEY_RE, SECRET_ASSIGN_RE, SECRET_RE
from lure.audit.findings import fingerprint

BEARER_RE = re.compile(r"\b(?:Bearer|Basic|token)\s+([A-Za-z0-9._~+/=-]{16,})", re.IGNORECASE)
REFERENCE_RE = re.compile(r"^(?:\$\{?[A-Za-z_]\w*\}?|env:|\{\{|<|%[A-Za-z_])")
GITLEAKS_TIMEOUT = 60
NO_GITLEAKS = "LURE_AUDIT_NO_GITLEAKS"


@dataclass(frozen=True)
class Hit:
    rule: str
    line: int
    fingerprint: str


def gitleaks_version() -> str | None:
    """gitleaks's version when it is installed and wanted, else None."""
    if os.environ.get(NO_GITLEAKS) or shutil.which("gitleaks") is None:
        return None
    try:
        done = subprocess.run(["gitleaks", "version"], capture_output=True, text=True,
                              timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return (done.stdout.strip() or None) if done.returncode == 0 else None


def _ignored(value: str) -> bool:
    value = value.strip().strip("\"'")
    return (not value or FAKE_SECRET_PREFIX in value or bool(REFERENCE_RE.match(value)))


def lure_hits(text: str, key: bytes) -> list[Hit]:
    hits = []
    for n, line in enumerate(text.splitlines(), 1):
        for m in SECRET_RE.finditer(line):
            if not _ignored(m.group(0)):
                hits.append(Hit("known key shape", n, fingerprint(m.group(0), key)))
        if PRIVATE_KEY_RE.search(line):
            hits.append(Hit("private key", n, fingerprint(line.strip(), key)))
        for name, value in SECRET_ASSIGN_RE.findall(line):
            if (len(value) >= 8 and re.search(r"\d", value) and not _ignored(value)
                    and not SECRET_RE.fullmatch(value)):
                hits.append(Hit(f"secret-named setting ({name})", n, fingerprint(value, key)))
        for m in BEARER_RE.finditer(line):
            if not _ignored(m.group(1)) and re.search(r"\d", m.group(1)):
                hits.append(Hit("authorization header", n, fingerprint(m.group(1), key)))
    return hits


def gitleaks_hits(text: str, key: bytes) -> list[Hit] | None:
    """gitleaks's findings in text, or None when it could not run. The
    report comes back redacted on a pipe; Lure takes the value from its own
    copy of the line, only to fingerprint it."""
    try:
        done = subprocess.run(
            ["gitleaks", "stdin", "--no-banner", "--redact", "--report-format", "json",
             "--report-path", "-", "--exit-code", "0", "--log-level", "error"],
            input=text, capture_output=True, text=True, timeout=GITLEAKS_TIMEOUT, check=False)
        report = json.loads(done.stdout or "[]")
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None
    lines = text.splitlines()
    hits = []
    for f in report if isinstance(report, list) else []:
        n = int(f.get("StartLine") or 0)
        line = lines[n - 1] if 0 < n <= len(lines) else ""
        start, end = max(int(f.get("StartColumn") or 1) - 1, 0), int(f.get("EndColumn") or 0)
        value = line[start:end] if end > start else line
        if _ignored(value) or FAKE_SECRET_PREFIX in line:
            continue
        hits.append(Hit(str(f.get("RuleID") or "gitleaks"), n, fingerprint(value.strip(), key)))
    return hits


def scan(text: str, key: bytes, use_gitleaks: bool) -> list[Hit]:
    """Every credential in text, once per line and fingerprint."""
    hits = lure_hits(text, key)
    if use_gitleaks:
        hits += gitleaks_hits(text, key) or []
    seen, out = set(), []
    for h in hits:
        if (h.line, h.fingerprint) not in seen:
            seen.add((h.line, h.fingerprint))
            out.append(h)
    return out
