"""The Gitea Actions examples in docs/ci/gitea/: they parse, trigger as
documented, pin every action, keep secrets out of commands, and every lure
command in them (the commented local-only options too) is one the CLI
accepts. Nothing is run against a model."""

import re
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from lure.cli import build_parser

REPO = Path(__file__).resolve().parent.parent
GITEA = REPO / "docs" / "ci" / "gitea"
FILES = sorted(GITEA.glob("*.yml"))
PINNED_RE = re.compile(r"^[\w.-]+/[\w.-]+@[0-9a-f]{40} # v\d+(\.\d+)*(-node20)?$")


def load(path):
    data = yaml.safe_load(path.read_text())
    data["on"] = data.pop(True)  # YAML 1.1 reads the key on as true
    return data


def steps(path):
    return [s for job in load(path)["jobs"].values() for s in job["steps"]]


def uses_lines(path):
    return [line.split("uses:", 1)[1].strip() for line in path.read_text().splitlines()
            if line.strip().startswith(("uses:", "- uses:"))]


def lure_commands(path):
    """Every lure command in the steps' run scripts, the commented-out
    options in them included, with line continuations joined."""
    text = "\n".join(s["run"] for s in steps(path) if "run" in s)
    lines = [re.sub(r"^\s*#\s?", "", line) if re.match(r"^\s*#\s+(lure |--)", line)
             else line for line in text.splitlines()]
    joined = re.sub(r"\\\n\s*", " ", "\n".join(lines))
    found = []
    for line in joined.splitlines():
        line = line.strip()
        if re.match(r"lure (run|report|retest|status|decide)\b", line):
            found.append(line.split(" || ")[0].strip())
    return found


def test_the_three_examples_exist():
    assert [p.name for p in FILES] == ["approval-check.yml", "lure-retest.yml", "lure-test.yml"]


def test_lure_test_runs_on_pull_requests_that_touch_profiles():
    on = load(GITEA / "lure-test.yml")["on"]
    assert on == {"pull_request": {"paths": ["profiles/**"]}}
    text = (GITEA / "lure-test.yml").read_text()
    assert "--repeat 3" in text and "--max-cost" in text and "--approval " in text
    assert any("upload-artifact" in u for u in uses_lines(GITEA / "lure-test.yml"))


def test_lure_retest_runs_weekly_and_on_profile_or_policy_pushes_and_fails_on_regression():
    data = load(GITEA / "lure-retest.yml")
    assert data["on"]["schedule"] == [{"cron": "0 6 * * 1"}]
    assert data["on"]["push"]["paths"] == ["profiles/**", "lure.yaml"]
    gate = next(s for s in steps(GITEA / "lure-retest.yml") if s.get("name") == "Gate on the retest")
    assert "1) " in gate["run"] and "exit 1" in gate["run"]


def test_the_approval_check_runs_lure_status_on_the_vetting_repo():
    path = GITEA / "approval-check.yml"
    data = load(path)
    assert set(data["on"]) == {"pull_request", "push"}
    checkout = next(s for s in steps(path) if s.get("name") == "Check out the vetting repository")
    assert checkout["with"]["repository"] == "${{ env.VETTING_REPO }}"
    assert checkout["with"]["token"] == "${{ secrets.VETTING_TOKEN }}"
    assert any(s.get("run") == 'lure status "$PROFILE"' for s in steps(path))


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_every_action_is_pinned_to_a_commit_with_its_version(path):
    uses = uses_lines(path)
    assert uses
    for u in uses:
        assert PINNED_RE.match(u), u
    for u in uses:
        if "upload-artifact" in u:
            assert "# v3." in u  # the official v4 stops on Gitea


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_secrets_stay_in_env_and_with_never_in_commands(path):
    for step in steps(path):
        assert "secrets." not in str(step.get("run", "")), step.get("name")
        assert "secrets." not in str(step.get("uses", ""))
    assert "GITHUB_STEP_SUMMARY" not in path.read_text()
    assert "permissions" in load(path) and load(path)["permissions"] == {"contents": "read"}


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_run_scripts_are_valid_bash(path):
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("no bash")
    for step in steps(path):
        if "run" in step:
            script = re.sub(r"\$\{\{[^}]*\}\}", "x", step["run"])
            result = subprocess.run([bash, "-n"], input=script, text=True, capture_output=True,
                                    check=False)
            assert result.returncode == 0, (step.get("name"), result.stderr)


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_every_lure_command_is_one_the_cli_accepts(path):
    commands = lure_commands(path)
    assert commands
    parser = build_parser()
    for command in commands:
        words = shlex.split(re.sub(r'"\$[\w{}]+"|\$[\w{}]+|\$\{\{[^}]*\}\}', "x", command))
        parser.parse_args(words[1:])


def test_the_local_only_option_keeps_target_and_judge_on_ollama():
    text = (GITEA / "lure-test.yml").read_text()
    local = [c for c in lure_commands(GITEA / "lure-test.yml") if "--target ollama" in c]
    assert local and "--judge-target ollama" in local[0]
    assert "LURE_OLLAMA_URL" in text
    assert "LURE_OLLAMA_URL" in (GITEA / "lure-retest.yml").read_text()


def test_the_examples_name_no_hosted_url_but_gitea_s_own():
    for path in FILES:
        urls = re.findall(r"https?://[^\s)\"']+", path.read_text())
        assert all(u.startswith(("https://<your-gitea>", "http://ollama.internal"))
                   for u in urls), (path.name, urls)
