"""Scenario packs: an attack's scenario field, a profile's scenarios, and the
approval page naming the packs tested."""

from dataclasses import replace

import pytest
import yaml

from lure.attacks import DEFAULT_SCENARIO, SCENARIOS, AttackError, load_attack
from lure.profiles import ProfileError, load_profile, select
from tests.test_attacks import repo, variant, write  # noqa: F401
from tests.test_gate import EXAMPLE, IPI_001, REPO

ATTACKS = [load_attack(p) for p in sorted((REPO / "attacks").glob("*/lure-*.yaml"))]


def test_scenario_defaults_to_accounts_payable_and_is_checked(repo):  # noqa: F811
    assert load_attack(write(repo, variant())).scenario == DEFAULT_SCENARIO
    attack = load_attack(write(repo, variant(scenario="it_helpdesk")))
    assert attack.scenario == "it_helpdesk"
    with pytest.raises(AttackError, match="scenario must be one of"):
        load_attack(write(repo, variant(scenario="retail")))


def test_every_current_attack_names_a_known_pack():
    assert {a.scenario for a in ATTACKS} <= set(SCENARIOS)


def _profile(tmp_path, **changes):
    data = {**EXAMPLE, "policy": str(REPO / "lure.yaml"), **changes}
    path = tmp_path / "p.yaml"
    path.write_text(yaml.safe_dump(data))
    return load_profile(path)


def test_profile_scenarios_choose_packs(tmp_path):
    helpdesk = replace(IPI_001, scenario="it_helpdesk")
    profile = _profile(tmp_path, scenarios=["accounts_payable"])
    chosen, skipped = select(profile, [IPI_001, helpdesk])
    assert chosen == [IPI_001]
    assert skipped[0].reason == "scenario pack it_helpdesk is not in the profile's scenarios"
    everything = _profile(tmp_path)
    assert everything.scenarios is None
    assert select(everything, [IPI_001, helpdesk])[0] == [IPI_001, helpdesk]


@pytest.mark.parametrize("value", [[], ["retail"], "accounts_payable", [1]])
def test_bad_scenarios_are_rejected(tmp_path, value):
    with pytest.raises(ProfileError, match="scenarios must be all or a list"):
        _profile(tmp_path, scenarios=value)


def test_approval_page_names_the_pack(tmp_path, monkeypatch):
    from tests.test_gate import TRIES, _approval

    md, html = _approval(tmp_path, monkeypatch, TRIES)
    assert ("from the scenario pack accounts payable (vendor email, invoices, payments): "
            "1 attack.") in md
    assert "from the scenario pack accounts payable" in html


@pytest.mark.parametrize("name, pack, attacks, gated", [
    ("example-support-agent", "customer_support",
     {"lure-cra-005", "lure-egr-004", "lure-ipi-011", "lure-ipi-012"}, {"issue_refund"}),
    ("example-helpdesk-agent", "it_helpdesk",
     {"lure-cra-006", "lure-egr-005", "lure-ipi-013"}, {"grant_access"}),
])
def test_pack_example_profiles_select_their_pack(name, pack, attacks, gated):
    profile = load_profile(REPO / "profiles" / f"{name}.yaml")
    chosen, skipped = select(profile, ATTACKS)
    assert {a.id for a in chosen} == attacks
    assert {a.scenario for a in chosen} == {pack}
    assert profile.gate.tools == gated
    assert any("scenario pack accounts_payable" in s.reason for s in skipped)


def test_attacks_from_unchosen_packs_collapse_to_one_line_per_pack():
    from lure.report.approval import _skipped

    skipped = [{"attack": "lure-ipi-001", "version": 1,
                "reason": "scenario pack accounts_payable is not in the profile's scenarios"},
               {"attack": "lure-ipi-002", "version": 1,
                "reason": "scenario pack accounts_payable is not in the profile's scenarios"},
               {"attack": "lure-tpo-001", "version": 1, "reason": "it adds third-party tools"}]
    assert _skipped(skipped) == [
        ("lure-tpo-001 v1", "it adds third-party tools"),
        ("2 attacks from the accounts payable pack", "not one of the profile's scenarios")]
