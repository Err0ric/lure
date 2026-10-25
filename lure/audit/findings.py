"""What lure audit reports: findings, their checks, severities and mappings.

A finding never holds a secret. It says what kind of thing was found, where
(a file and line, or a profile key), a short fingerprint when it is a
credential, and a plain-language fix. The fingerprint is a salted HMAC, so
the same secret has the same fingerprint across runs on one checkout, but a
report cannot be used to recover or guess it.

IDs verified 2026-10-25: ATLAS in MITRE's data release 2026.09, ATT&CK on
attack.mitre.org, OWASP Top 10 for LLM Applications 2025 on genai.owasp.org.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
INFO = "info"
SEVERITIES = (CRITICAL, HIGH, MEDIUM, INFO)

OWASP = {
    "LLM01:2025": "Prompt Injection",
    "LLM02:2025": "Sensitive Information Disclosure",
    "LLM03:2025": "Supply Chain",
    "LLM05:2025": "Improper Output Handling",
    "LLM06:2025": "Excessive Agency",
    "LLM07:2025": "System Prompt Leakage",
}


@dataclass(frozen=True)
class Check:
    number: int
    key: str
    title: str
    severity: str
    atlas: tuple[str, ...]
    attack: tuple[str, ...]
    owasp: tuple[str, ...]


CHECKS = {c.key: c for c in (
    Check(1, "credentials", "Hardcoded credential", CRITICAL,
          ("AML.T0055", "AML.T0083"), ("T1552.001",), ("LLM02:2025", "LLM07:2025")),
    Check(2, "auto_approve", "Acts without asking", CRITICAL,
          ("AML.T0053", "AML.M0029"), (), ("LLM06:2025",)),
    Check(3, "ungated_tool", "Risky tool with no confirmation step", HIGH,
          ("AML.T0053", "AML.M0029", "AML.M0028"), (), ("LLM06:2025",)),
    Check(4, "privileged_credential", "Over-privileged credential", INFO,
          ("AML.T0012", "AML.M0026"), ("T1078",), ("LLM06:2025",)),
    Check(5, "unrestricted_egress", "Unrestricted outbound access", HIGH,
          ("AML.T0086", "AML.T0077"), ("T1048", "T1567"), ("LLM02:2025", "LLM05:2025")),
    Check(6, "model_endpoint", "Model endpoint outside the declared provider", CRITICAL,
          ("AML.T0081",), ("T1557",), ("LLM03:2025", "LLM02:2025")),
    Check(7, "mcp_hygiene", "MCP server or tool hygiene", HIGH,
          ("AML.T0010.005", "AML.T0109", "AML.T0110"), ("T1195.001", "T1557"),
          ("LLM03:2025", "LLM01:2025")),
    Check(8, "prompt_hygiene", "System prompt hygiene", INFO,
          ("AML.T0056", "AML.T0069.002"), (), ("LLM07:2025",)),
    Check(9, "instruction_origin", "Instructions from outside the repository", HIGH,
          ("AML.T0051.001", "AML.T0112.000"), ("T1204.002",), ("LLM01:2025",)),
    Check(10, "external_persistence", "Memory, logs or transcripts kept outside", INFO,
          ("AML.T0080.000", "AML.T0057"), ("T1530",), ("LLM02:2025",)),
    Check(12, "mcp_allowlist", "MCP server not on the approved list", CRITICAL,
          ("AML.T0010.005", "AML.T0109"), ("T1195.001",), ("LLM03:2025",)),
)}


@dataclass(frozen=True)
class Finding:
    check: str
    severity: str
    what: str
    location: str
    fix: str
    # For a credential: a salted HMAC prefix, never the value.
    fingerprint: str | None = None
    # Narrower mappings for this finding; the check's own when empty.
    atlas: tuple[str, ...] = ()
    attack: tuple[str, ...] = ()

    @property
    def meta(self) -> Check:
        return CHECKS[self.check]

    def to_dict(self) -> dict[str, Any]:
        c = self.meta
        return {"check": c.number, "key": c.key, "title": c.title, "severity": self.severity,
                "what": self.what, "location": self.location, "fix": self.fix,
                **({"fingerprint": self.fingerprint} if self.fingerprint else {}),
                "atlas": list(self.atlas or c.atlas), "attack": list(self.attack or c.attack),
                "owasp": list(c.owasp)}


@dataclass
class AuditResult:
    profile: str
    profile_sha256: str
    findings: list[Finding] = field(default_factory=list)
    # How credentials were scanned: gitleaks <version>, or lure patterns.
    scanner: str = "lure patterns"

    @property
    def critical(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == CRITICAL]

    @property
    def blocked(self) -> bool:
        return bool(self.critical)

    def counts(self) -> dict[str, int]:
        return {s: sum(f.severity == s for f in self.findings) for s in SEVERITIES}

    def to_dict(self) -> dict[str, Any]:
        order = {s: i for i, s in enumerate(SEVERITIES)}
        return {"audit_version": 1, "profile": self.profile, "profile_sha256": self.profile_sha256,
                "scanner": self.scanner, "blocked": self.blocked, "counts": self.counts(),
                "findings": [f.to_dict() for f in sorted(
                    self.findings, key=lambda f: (order[f.severity], f.meta.number, f.location))]}


DEFAULT_SALT = Path("vetting") / ".audit-salt"


def salt(path: Path | None = None) -> bytes:
    """This checkout's fingerprint salt, created on first use (gitignored)."""
    path = path or Path(os.environ.get("LURE_AUDIT_SALT_FILE", DEFAULT_SALT))
    try:
        return bytes.fromhex(path.read_text().strip())
    except (FileNotFoundError, ValueError):
        path.parent.mkdir(parents=True, exist_ok=True)
        value = secrets.token_hex(32)
        path.write_text(value + "\n")
        path.chmod(0o600)
        return bytes.fromhex(value)


def fingerprint(secret: str, key: bytes) -> str:
    """12 hex characters of HMAC-SHA256(salt, secret)."""
    return hmac.new(key, secret.encode(), hashlib.sha256).hexdigest()[:12]
