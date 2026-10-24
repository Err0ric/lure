"""The Arcanum Prompt Injection Taxonomy, mapped alongside ATLAS.

Based on the Arcanum Prompt Injection Taxonomy by Jason Haddix, Arcanum
Information Security (arcanum-sec.com). Lure is not affiliated with or
endorsed by Arcanum Information Security. The data is a vendored, unmodified
copy of v1.6.1 (CC BY 4.0); SOURCE.md records the commit and hashes.

An attack's `arcanum:` block lists codes per pillar. Every code must exist
in taxonomy.json under that pillar; nothing is taken from memory. Variants
add codes by kind, the way encoded variants add the ATLAS obfuscation ID.
"""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path
from typing import Any

DATA = Path(__file__).with_name("taxonomy.json")
VERSION = "1.6.1"
# The upstream commit the vendored files come from (SOURCE.md).
COMMIT = "e02cf5b6e202f195c6b6c01484e99519f797acc6"
ATTRIBUTION = ("Based on the Arcanum Prompt Injection Taxonomy by Jason Haddix, "
               "Arcanum Information Security (arcanum-sec.com).")
DISCLAIMER = "Lure is not affiliated with or endorsed by Arcanum Information Security."
URL = "https://www.arcanum-sec.com/pitax"

# Lure's pillar key, the taxonomy.json array and the code prefix, in the
# order attack files and reports list them.
PILLARS = {
    "input": ("inputs", "PIT-N"),
    "intent": ("intents", "PIT-I"),
    "technique": ("techniques", "PIT-T"),
    "evasion": ("evasions", "PIT-E"),
}

# Codes a variant adds by kind (and encoding): split payloads are Payload
# Splitting, an alias of PIT-T-24; encodings are their evasions. Buried and
# rephrased add none.
SPLIT_CODES = {"technique": ["PIT-T-24"]}
ENCODING_CODES = {
    "base64": {"evasion": ["PIT-E-07"]},
    "rot13": {"evasion": ["PIT-E-14"]},
    "hex": {"evasion": ["PIT-E-21"]},
}


@cache
def nodes() -> dict[str, dict[str, Any]]:
    """Every node by code, with its Lure pillar key added as `pillar`."""
    data = json.loads(DATA.read_text(encoding="utf-8"))
    out: dict[str, dict[str, Any]] = {}
    for pillar, (key, _) in PILLARS.items():
        for node in data[key]:
            out[node["code"]] = {**node, "pillar": pillar}
    return out


def title(code: str) -> str:
    node = nodes().get(code)
    return node["title"] if node else code


def problems(mapping: Any) -> list[str]:
    """What is wrong with an `arcanum:` block, if anything."""
    if not isinstance(mapping, dict):
        return ["arcanum must be a mapping of pillar to a list of codes"]
    out = []
    for pillar, codes in mapping.items():
        if pillar not in PILLARS:
            out.append(f"arcanum: unknown pillar {pillar!r} (one of {list(PILLARS)})")
            continue
        if not isinstance(codes, list) or not all(isinstance(c, str) for c in codes):
            out.append(f"arcanum.{pillar} must be a list of codes")
            continue
        if len(set(codes)) != len(codes):
            out.append(f"arcanum.{pillar} lists a code twice")
        for code in codes:
            node = nodes().get(code)
            if node is None:
                out.append(f"arcanum.{pillar}: {code} is not in the Arcanum taxonomy v{VERSION}")
            elif node["pillar"] != pillar:
                out.append(f"arcanum.{pillar}: {code} is a {node['pillar']} code")
    return out


def merge(*mappings: dict[str, list[str]]) -> dict[str, list[str]]:
    """Codes from every mapping, per pillar in PILLARS order, first seen first."""
    out: dict[str, list[str]] = {}
    for pillar in PILLARS:
        codes: list[str] = []
        for m in mappings:
            codes += [c for c in m.get(pillar, []) if c not in codes]
        if codes:
            out[pillar] = codes
    return out
