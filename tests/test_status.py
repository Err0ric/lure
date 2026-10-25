"""lure status: is the profile approved as it is now? The gate a tool's own
CI runs. No network, no model."""

import io
import shutil

import pytest

from lure import cli
from lure.profiles import load_profile
from lure.vetting import APPROVED_STATE, CHANGED, REJECTED, UNDECIDED, status
from tests.test_decide import EXAMPLE, make_run


@pytest.fixture
def setup(tmp_path):
    """A copy of the example profile, a run of it, and an empty vetting dir."""
    profile_path = tmp_path / "profiles" / "example-ap-agent.yaml"
    profile_path.parent.mkdir()
    shutil.copy(EXAMPLE, profile_path)
    shutil.copy(EXAMPLE.parent.parent / "lure.yaml", tmp_path / "lure.yaml")
    make_run(tmp_path / "results", load_profile(profile_path))
    return tmp_path, profile_path


def decide(tmp_path, profile_path, decision, *extra):
    args = ["decide", str(profile_path), "--decision", decision, "--by", "AP operations lead",
            "--results-dir", str(tmp_path / "results"), "--vetting-dir", str(tmp_path / "vetting")]
    assert cli.main([*args, *extra], io.StringIO()) == cli.EXIT_OK


def check(tmp_path, profile_path):
    out = io.StringIO()
    code = cli.main(["status", str(profile_path), "--vetting-dir", str(tmp_path / "vetting")], out)
    return code, out.getvalue()


def test_no_decision_is_not_approved(setup):
    tmp_path, profile_path = setup
    code, out = check(tmp_path, profile_path)
    assert code == cli.EXIT_POLICY_FAIL
    assert "example-ap-agent is not approved: no decision recorded" in out
    assert status(load_profile(profile_path), tmp_path / "vetting").state == UNDECIDED


@pytest.mark.parametrize("decision, extra", [
    ("approve", ()),
    ("approve-with-conditions", ("--conditions", "Remove drive_read.")),
])
def test_an_approval_of_the_profile_as_it_is_passes(setup, decision, extra):
    tmp_path, profile_path = setup
    decide(tmp_path, profile_path, decision, *extra)
    code, out = check(tmp_path, profile_path)
    assert code == cli.EXIT_OK
    assert f"example-ap-agent is approved: {decision}, and the profile is unchanged" in out
    assert "Decision:  " + decision + " by AP operations lead" in out
    if extra:
        assert "  condition: Remove drive_read." in out
    assert status(load_profile(profile_path), tmp_path / "vetting").state == APPROVED_STATE


def test_the_latest_decision_wins_so_a_later_reject_fails(setup):
    tmp_path, profile_path = setup
    decide(tmp_path, profile_path, "approve")
    decide(tmp_path, profile_path, "reject")
    code, out = check(tmp_path, profile_path)
    assert code == cli.EXIT_POLICY_FAIL
    assert "the latest decision rejects example-ap-agent" in out
    assert status(load_profile(profile_path), tmp_path / "vetting").state == REJECTED


def test_a_reapproval_after_a_reject_passes_again(setup):
    tmp_path, profile_path = setup
    decide(tmp_path, profile_path, "reject")
    decide(tmp_path, profile_path, "approve")
    assert check(tmp_path, profile_path)[0] == cli.EXIT_OK


def test_a_profile_changed_since_the_approval_fails(setup):
    tmp_path, profile_path = setup
    decide(tmp_path, profile_path, "approve")
    profile_path.write_text(profile_path.read_text().replace("Be concise.", "Be brief."))
    code, out = check(tmp_path, profile_path)
    assert code == cli.EXIT_POLICY_FAIL
    assert "the profile changed since it was approved" in out
    assert "retest it and record a new decision" in out
    assert status(load_profile(profile_path), tmp_path / "vetting").state == CHANGED


def test_a_changed_prompt_file_counts_as_a_changed_profile(tmp_path):
    profile_path = tmp_path / "profiles" / "p.yaml"
    profile_path.parent.mkdir()
    shutil.copy(EXAMPLE.parent.parent / "lure.yaml", tmp_path / "lure.yaml")
    text = EXAMPLE.read_text()
    start, end = text.index("system_prompt: >-"), text.index("\n# Each of the agent's tools")
    profile_path.write_text(text[:start] + "system_prompt_file: p.prompt.txt" + text[end:])
    (profile_path.parent / "p.prompt.txt").write_text("You are an AP assistant. Be concise.\n")
    make_run(tmp_path / "results", load_profile(profile_path))
    decide(tmp_path, profile_path, "approve")
    assert check(tmp_path, profile_path)[0] == cli.EXIT_OK
    (profile_path.parent / "p.prompt.txt").write_text("You are an AP assistant. Be brief.\n")
    code, out = check(tmp_path, profile_path)
    assert code == cli.EXIT_POLICY_FAIL and "the profile changed" in out


def test_bad_input_is_exit_2(setup, capsys):
    tmp_path, profile_path = setup
    log = tmp_path / "vetting" / "example-ap-agent" / "decisions.jsonl"
    log.parent.mkdir(parents=True)
    log.write_text("{not json\n")
    assert check(tmp_path, profile_path)[0] == cli.EXIT_BAD_INPUT
    assert "not valid JSON" in capsys.readouterr().err
    assert cli.main(["status", str(tmp_path / "missing.yaml")], io.StringIO()) == (
        cli.EXIT_BAD_INPUT)
