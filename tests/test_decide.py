"""lure decide: the append-only decision log. No network, no model."""

import io
import json
from pathlib import Path

import pytest

from lure import cli
from lure.profiles import load_profile
from lure.vetting import (
    VettingError,
    append_decision,
    decision_record,
    last_approved,
    pick_run,
    read_decisions,
)

REPO = Path(__file__).resolve().parent.parent
EXAMPLE = REPO / "profiles" / "example-ap-agent.yaml"


def make_run(root, profile, stamp="20261024T100000Z", sha=None):
    folder = Path(root) / profile.name / stamp
    folder.mkdir(parents=True)
    (folder / "manifest.json").write_text(json.dumps({
        "manifest_version": 1, "lure_version": "1.5.0",
        "profile": {"name": profile.name, "sha256": sha or profile.sha256,
                    "tools": [{"name": t.name, "maps_to": t.maps_to} for t in profile.tools]},
        "target": "anthropic:claude-haiku-5-5", "judge": "rules", "repeat": 3,
        "variants": "none", "runs": [], "skipped": []}))
    return folder


def decide(tmp_path, *args):
    out = io.StringIO()
    code = cli.main(["decide", str(EXAMPLE), "--results-dir", str(tmp_path / "results"),
                     "--vetting-dir", str(tmp_path / "vetting"), *args], out)
    return code, out.getvalue()


def test_decide_appends_one_line_per_decision(tmp_path):
    profile = load_profile(EXAMPLE)
    make_run(tmp_path / "results", profile, "20261024T090000Z")
    latest = make_run(tmp_path / "results", profile, "20261024T100000Z")
    code, out = decide(tmp_path, "--decision", "approve-with-conditions",
                       "--by", "AP operations lead", "--conditions",
                       "Require a person to confirm before ap_mail_send sends outside.",
                       "Remove drive_read.")
    assert code == 0
    assert "Logged:" in out and "line 1" in out
    code, out = decide(tmp_path, "--decision", "reject", "--by", "Security lead",
                       "--notes", "Retest failed.")
    assert code == 0 and "line 2" in out
    log = tmp_path / "vetting" / "example-ap-agent" / "decisions.jsonl"
    lines = log.read_text().splitlines()
    assert len(lines) == 2
    first, second = (json.loads(x) for x in lines)
    assert first["decision"] == "approve-with-conditions" and first["by"] == "AP operations lead"
    assert first["conditions"] == ["Require a person to confirm before ap_mail_send sends outside.",
                                   "Remove drive_read."]
    assert first["run"] == str(latest) and first["profile_sha256"] == profile.sha256
    assert first["target"] == "anthropic:claude-haiku-5-5" and first["decision_version"] == 1
    assert second["decision"] == "reject" and second["conditions"] == []
    assert second["notes"] == "Retest failed."
    # A later reject does not hide what was approved.
    assert last_approved(read_decisions(tmp_path / "vetting", "example-ap-agent")) == first


def test_earlier_lines_are_kept_byte_for_byte(tmp_path):
    profile = load_profile(EXAMPLE)
    make_run(tmp_path / "results", profile)
    decide(tmp_path, "--decision", "approve", "--by", "AP operations lead")
    log = tmp_path / "vetting" / "example-ap-agent" / "decisions.jsonl"
    before = log.read_bytes()
    decide(tmp_path, "--decision", "reject", "--by", "AP operations lead")
    assert log.read_bytes().startswith(before)


def test_a_hand_edited_log_without_a_last_newline_still_appends(tmp_path):
    profile = load_profile(EXAMPLE)
    run = make_run(tmp_path / "results", profile)
    log = tmp_path / "vetting" / "example-ap-agent" / "decisions.jsonl"
    log.parent.mkdir(parents=True)
    log.write_text(json.dumps({"decision": "reject", "profile": profile.name}))
    record = decision_record(profile, run, "approve", "Security lead")
    _, line = append_decision(tmp_path / "vetting", record)
    assert line == 2 and len(read_decisions(tmp_path / "vetting", profile.name)) == 2


@pytest.mark.parametrize("args,message", [
    (["--decision", "approve-with-conditions", "--by", "Lead"], "needs at least one --conditions"),
    (["--decision", "approve", "--by", "Lead", "--conditions", "x"], "takes no conditions"),
    (["--decision", "reject", "--by", "  "], "--by must name who decided"),
])
def test_bad_decisions_exit_2_and_log_nothing(tmp_path, capsys, args, message):
    make_run(tmp_path / "results", load_profile(EXAMPLE))
    code, _ = decide(tmp_path, *args)
    assert code == 2 and message in capsys.readouterr().err
    assert not (tmp_path / "vetting").exists()


def test_unknown_decision_is_a_usage_error(tmp_path):
    with pytest.raises(SystemExit) as e:
        decide(tmp_path, "--decision", "maybe", "--by", "Lead")
    assert e.value.code == 2


def test_no_run_or_wrong_run_is_an_error(tmp_path, capsys):
    profile = load_profile(EXAMPLE)
    code, _ = decide(tmp_path, "--decision", "approve", "--by", "Lead")
    assert code == 2 and "no runs of example-ap-agent" in capsys.readouterr().err
    with pytest.raises(VettingError, match="is not a profile run"):
        pick_run(profile, tmp_path, tmp_path)


def test_a_run_of_another_profile_or_an_older_profile_file_is_refused(tmp_path):
    profile = load_profile(EXAMPLE)
    stale = make_run(tmp_path / "results", profile, sha="0" * 64)
    with pytest.raises(VettingError, match="changed since .* ran"):
        pick_run(profile, stale, tmp_path / "results")
    other = load_profile(REPO / "profiles" / "example-ops-agent.yaml")
    folder = make_run(tmp_path / "results", other)
    with pytest.raises(VettingError, match="is a run of 'example-ops-agent'"):
        pick_run(profile, folder, tmp_path / "results")


def test_a_corrupt_log_line_is_reported(tmp_path):
    log = tmp_path / "vetting" / "example-ap-agent" / "decisions.jsonl"
    log.parent.mkdir(parents=True)
    log.write_text('{"decision": "approve"}\nnot json\n')
    with pytest.raises(VettingError, match="line 2: not valid JSON"):
        read_decisions(tmp_path / "vetting", "example-ap-agent")
