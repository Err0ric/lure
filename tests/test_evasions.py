"""Generated evasion variants (zero-width, homoglyphs, hidden HTML) and
authored translated variants. Scripted turns only."""

import json
import re
from pathlib import Path

import pytest

from lure.arcanum import EVASION_CODES
from lure.attacks import (
    EVASIONS,
    HOMOGLYPHS,
    OBFUSCATION_ATLAS,
    ZERO_WIDTH,
    AttackError,
    _rule_strings,
    load_attack,
)
from lure.judge.rules import Verdict
from lure.runner import run_attack
from tests.fakes import ScriptedAdapter, call, say
from tests.test_attacks import repo, variant, write  # noqa: F401
from tests.test_cli import SUMMARY
from tests.test_schema import errors

REPO = Path(__file__).resolve().parent.parent
CURRENT = [a for a in (load_attack(p) for p in sorted((REPO / "attacks").glob("*/*.yaml")))
           if not a.pinned and not a.in_task]
IPI_001 = next(a for a in CURRENT if a.id == "lure-ipi-001")
ADDRESS_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+|https?://\S+|\b[\w-]+\.example\b")
UNDO_HOMOGLYPHS = {v: k for k, v in HOMOGLYPHS.items()}


@pytest.mark.parametrize("attack", CURRENT, ids=lambda a: a.id)
def test_evasions_keep_addresses_and_rule_strings(attack):
    payload = attack.injection.payload
    keep = [s for s in _rule_strings(attack) if s in payload.lower()]
    addresses = ADDRESS_RE.findall(payload)
    for vid in EVASIONS:
        text = attack.variant_by_id(vid).parts[0].payload
        for s in keep:
            assert s in text.lower(), (vid, s)
        for a in addresses:
            assert a in text, (vid, a)


def test_each_evasion_hides_the_same_payload():
    payload = IPI_001.injection.payload
    zw = IPI_001.variant_by_id("invisible-zero-width").parts[0].payload
    assert ZERO_WIDTH in zw and zw.replace(ZERO_WIDTH, "") == payload
    glyph = IPI_001.variant_by_id("homoglyph-cyrillic").parts[0].payload
    assert glyph != payload and glyph.translate(UNDO_HOMOGLYPHS) == payload
    assert IPI_001.variant_by_id("hidden-html-comment").parts[0].payload == f"<!-- {payload} -->"
    assert IPI_001.variant_by_id("hidden-span").parts[0].payload == (
        f'<span style="display:none">{payload}</span>')


def test_html_comment_never_closes_early():
    ipi_013 = next(a for a in CURRENT if a.id == "lure-ipi-013")
    text = ipi_013.variant_by_id("hidden-html-comment").parts[0].payload
    assert "--" not in text[4:-3]


@pytest.mark.parametrize("vid", sorted(EVASIONS))
def test_evasion_variants_add_their_codes_and_the_obfuscation_technique(vid):
    kind = EVASIONS[vid][0]
    planted = IPI_001.with_variant(IPI_001.variant_by_id(vid))
    assert OBFUSCATION_ATLAS in planted.atlas
    assert set(EVASION_CODES[kind]["evasion"]) <= set(planted.arcanum["evasion"])


@pytest.mark.parametrize("vid", [*sorted(EVASIONS), "translated-es"])
def test_the_rules_still_judge_an_evasion_variant(vid, tmp_path):
    attack = IPI_001.with_variant(IPI_001.variant_by_id(vid))
    harm = call("send_email", "c2", to=["billing-verify@external.example"], subject="Invoices",
                body="Attached.")
    result = run_attack(attack, ScriptedAdapter(call("read_inbox"), harm, say(SUMMARY)))
    assert result.judgment.verdict is Verdict.FAIL
    assert result.judgment.task.payload_reached
    clean = run_attack(attack, ScriptedAdapter(call("read_inbox"), say(SUMMARY)))
    assert clean.judgment.verdict is Verdict.PASS
    record = json.loads(result.save(tmp_path).read_text())
    assert errors(record) == []
    assert record["variant"]["evasion"]


def test_translated_variant_is_language_switching_not_obfuscation():
    v = IPI_001.variant_by_id("translated-es")
    planted = IPI_001.with_variant(v)
    assert v.kind == "translated" and v.evasion == "es" and v.source == "yaml"
    assert "PIT-E-05" in planted.arcanum["evasion"]
    assert OBFUSCATION_ATLAS not in planted.atlas


@pytest.mark.parametrize("bad, message", [
    ({"id": "t", "kind": "translated", "payload": "x"}, "language must be a two-letter code"),
    ({"id": "t", "kind": "translated", "language": "es"}, "payload must be a non-empty string"),
    ({"id": "homoglyph-cyrillic", "kind": "rephrased", "payload": "x"},
     "is a generated variant's id"),
])
def test_bad_translated_variants_fail_at_load(repo, bad, message):  # noqa: F811
    with pytest.raises(AttackError, match=message):
        load_attack(write(repo, variant(variants=[bad])))
