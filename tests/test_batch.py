from collections import Counter
from dataclasses import dataclass

import pytest

from lure.attacks import AttackError
from lure.batch import SummaryRow, collect_attack_paths, summarize
from lure.judge.rules import Verdict

P, R, I, F, E = Verdict.PASS, Verdict.REVIEW, Verdict.INVALID, Verdict.FAIL, Verdict.ERROR


# collect_attack_paths


def test_file_returns_itself(tmp_path):
    f = tmp_path / "lure-ipi-001.yaml"
    f.write_text("x")
    assert collect_attack_paths(f) == [f]


def test_folder_is_recursive_sorted_and_yaml_only(tmp_path):
    for rel in ["b/lure-ipi-002.yaml", "a/lure-ipi-003.yaml", "lure-dpi-001.yaml",
                "notes.md", "a/.gitkeep", "a/data.json"]:
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x")
    found = [p.relative_to(tmp_path).as_posix() for p in collect_attack_paths(tmp_path)]
    assert found == ["a/lure-ipi-003.yaml", "b/lure-ipi-002.yaml", "lure-dpi-001.yaml"]


def test_empty_folder(tmp_path):
    (tmp_path / ".gitkeep").write_text("")
    with pytest.raises(AttackError, match="no attack files"):
        collect_attack_paths(tmp_path)


def test_missing_path(tmp_path):
    with pytest.raises(AttackError, match="not found"):
        collect_attack_paths(tmp_path / "nope")


# summarize and rates


@dataclass
class _Attack:
    id: str


@dataclass
class _Judgment:
    verdict: Verdict


@dataclass
class _Result:
    attack: _Attack
    judgment: _Judgment


def results(attack_id, *verdicts):
    return [_Result(_Attack(attack_id), _Judgment(v)) for v in verdicts]


def test_summarize_groups_in_first_seen_order():
    rows = summarize(results("lure-ipi-002", P) + results("lure-ipi-001", F, F)
                     + results("lure-ipi-002", R))
    assert [r.attack_id for r in rows] == ["lure-ipi-002", "lure-ipi-001"]
    assert rows[0].counts == Counter({P: 1, R: 1})
    assert rows[1].runs == 2


def test_rates_leave_out_invalid_and_error_but_keep_review():
    [row] = summarize(results("lure-ipi-001", P, R, F, F, I, E))
    assert row.runs == 6
    assert row.scored == 4
    assert row.pass_rate == pytest.approx(1 / 4)
    assert row.asr == pytest.approx(2 / 4)


def test_rates_none_when_nothing_scored():
    row = SummaryRow("lure-ipi-001", Counter({I: 2, E: 1}))
    assert row.scored == 0
    assert row.pass_rate is None and row.asr is None
