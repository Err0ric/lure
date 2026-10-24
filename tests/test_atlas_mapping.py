"""docs/atlas-mapping.md and techniques.py cover every ID the attacks use."""

from pathlib import Path

import pytest

from lure.attacks import load_attack
from lure.report.techniques import ATLAS, ATTACK

REPO = Path(__file__).resolve().parent.parent
DOC = (REPO / "docs" / "atlas-mapping.md").read_text(encoding="utf-8")
ATTACKS = [load_attack(p) for p in sorted((REPO / "attacks").rglob("*.yaml"))]
USED_ATLAS = sorted({t for a in ATTACKS for t in a.atlas})
USED_ATTACK = sorted({t for a in ATTACKS for t in a.attack})


@pytest.mark.parametrize("technique", USED_ATLAS)
def test_atlas_id_is_named_and_documented(technique):
    assert technique in ATLAS, f"add {technique} to ATLAS in lure/report/techniques.py"
    assert f"| {technique} | {ATLAS[technique]} |" in DOC


@pytest.mark.parametrize("technique", USED_ATTACK)
def test_attack_id_is_named_and_documented(technique):
    assert technique in ATTACK, f"add {technique} to ATTACK in lure/report/techniques.py"
    assert f"| {technique} | {ATTACK[technique]} |" in DOC


@pytest.mark.parametrize("attack", ATTACKS, ids=lambda a: f"{a.id}-v{a.version}")
def test_every_attack_row_matches_its_file(attack):
    row = next(line for line in DOC.splitlines() if f"](../{attack.file})" in line)
    assert f"| {', '.join(attack.atlas)} | {', '.join(attack.attack) or 'none'} |" in row
