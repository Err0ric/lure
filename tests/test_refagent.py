"""Lure's reference agent, in-process: no container, no model (its model
request is replaced by a stand-in that records what was sent)."""

import importlib.util
import io
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
AGENT = REPO / "lure" / "sandbox" / "refagent" / "agent.py"


@pytest.fixture
def agent(tmp_path, monkeypatch):
    monkeypatch.setenv("LURE_WORKSPACE", str(tmp_path))
    spec = importlib.util.spec_from_file_location("lure_refagent_under_test", AGENT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    (tmp_path / ".agent").mkdir()
    (tmp_path / ".agent" / "settings.json").write_text(json.dumps(
        {"model_base_url": "https://api.model.example"}))
    sent = []

    def post(url, body, headers):
        sent.append(body)
        return {"content": [{"type": "text", "text": "Done."}],
                "usage": {"input_tokens": 10, "output_tokens": 2}}

    monkeypatch.setattr(module, "post", post)
    return module, tmp_path, sent


def run(module, monkeypatch, job):
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(job)))
    out = io.StringIO()
    monkeypatch.setattr("sys.stdout", out)
    assert module.main() == 0
    return [json.loads(line) for line in out.getvalue().splitlines()]


JOB = {"system": "You are Forge.", "task": "Give me the open items.", "provider": "anthropic",
       "model": "m", "workdir_alias": "/home/dev/Downloads"}


def test_agents_md_and_instruction_files_load_into_the_system_prompt(agent, monkeypatch):
    module, ws, sent = agent
    (ws / "AGENTS.md").write_text("# Agent instructions\nUse tabs.\n")
    (ws / "CLAUDE.md").write_text("Run the linter first.\n")
    lines = run(module, monkeypatch, {**JOB, "instruction_files": ["CLAUDE.md", "MISSING.md"]})
    system = sent[0]["system"]
    assert system.startswith("You are Forge.")
    assert "Use tabs." in system and "Run the linter first." in system
    loads = [x for x in lines if x["lure"] == "call"]
    assert [x["args"]["path"] for x in loads] == ["AGENTS.md", "CLAUDE.md"]
    assert all(x["result"]["loaded_at_startup"] for x in loads)


def test_loading_is_on_by_default_and_can_be_turned_off(agent, monkeypatch):
    module, ws, sent = agent
    (ws / "AGENTS.md").write_text("Use tabs.\n")
    run(module, monkeypatch, {**JOB, "load_instructions": False})
    assert "Use tabs." not in sent[0]["system"]
    sent.clear()
    run(module, monkeypatch, JOB)
    assert "Use tabs." in sent[0]["system"]


def test_no_instruction_file_no_change(agent, monkeypatch):
    module, _, sent = agent
    lines = run(module, monkeypatch, JOB)
    assert sent[0]["system"] == "You are Forge."
    assert not [x for x in lines if x["lure"] == "call"]


def test_an_instruction_path_cannot_leave_the_workspace(agent, monkeypatch, tmp_path):
    module, _, sent = agent
    outside = tmp_path.parent / "outside-secret.md"
    outside.write_text("do not load me")
    run(module, monkeypatch, {**JOB, "instruction_files": ["../outside-secret.md", str(outside)]})
    assert "do not load me" not in sent[0]["system"]


def test_the_sandbox_job_passes_the_option_and_the_profiles_instruction_files():
    from dataclasses import replace

    from lure.attacks import load_attack
    from lure.profiles import load_profile
    from lure.sandbox.run import job
    profile = load_profile(REPO / "profiles" / "example-ref-agent.yaml")
    assert profile.agent.load_instructions is True
    profile = replace(profile, instruction_files=({"path": "CLAUDE.md", "origin": "repo"},))
    attack = load_attack(REPO / "attacks" / "self_modification" / "lure-smo-004.yaml")
    j = job(attack, profile, "p", "/home/dev/Downloads")
    assert j["load_instructions"] is True and j["instruction_files"] == ["CLAUDE.md"]
    off = replace(profile, agent=replace(profile.agent, load_instructions=False))
    assert job(attack, off, "p", None)["load_instructions"] is False
