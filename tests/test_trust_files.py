"""Trust files: SECURITY.md, the GitHub issue and pull request templates,
and the container (Dockerfile, .dockerignore)."""

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def test_security_policy_says_how_to_report_and_what_is_supported():
    text = (REPO / "SECURITY.md").read_text(encoding="utf-8")
    assert "https://github.com/Err0ric/lure/security/advisories/new" in text
    assert "do not open a public issue" in text
    for heading in ("## Report a vulnerability", "## Supported versions", "## In scope",
                    "## Out of scope"):
        assert heading in text
    assert re.search(r"currently \d+\.\d+\.x", text)
    assert "@" not in re.sub(r"https?://\S+", "", text)  # no invented contact address


def _yaml(path):
    import yaml

    return yaml.safe_load(path.read_text(encoding="utf-8"))


FORMS = sorted((REPO / ".github" / "ISSUE_TEMPLATE").glob("*.yml"))


def test_issue_forms_are_valid_and_blank_issues_point_to_the_security_policy():
    config = _yaml(REPO / ".github" / "ISSUE_TEMPLATE" / "config.yml")
    assert config["blank_issues_enabled"] is False
    assert config["contact_links"][0]["url"] == (
        "https://github.com/Err0ric/lure/security/advisories/new")
    forms = [f for f in FORMS if f.name != "config.yml"]
    assert {f.name for f in forms} == {"bug_report.yml", "attack_idea.yml",
                                       "feature_request.yml"}
    for f in forms:
        form = _yaml(f)
        assert form["name"] and form["description"] and form["body"], f.name
        ids = [item["id"] for item in form["body"] if "id" in item]
        assert len(ids) == len(set(ids)), f.name
        assert all(item["type"] in ("markdown", "input", "textarea", "dropdown", "checkboxes")
                   for item in form["body"]), f.name
        assert any(item.get("validations", {}).get("required") for item in form["body"]), f.name


def test_the_bug_form_asks_for_redaction_and_sends_vulnerabilities_elsewhere():
    text = (REPO / ".github" / "ISSUE_TEMPLATE" / "bug_report.yml").read_text()
    assert "SECURITY.md" in text and "I removed real prompts, keys and customer data" in text


def test_the_pull_request_template_covers_the_contributing_checklist():
    template = (REPO / ".github" / "PULL_REQUEST_TEMPLATE.md").read_text(encoding="utf-8")
    for phrase in ("`pytest` and `ruff check .` pass", "Fake data only", "ATLAS", "ATT&CK",
                   "schema_version", "Docs updated", "No em dashes", "Mock tools only"):
        assert phrase in template, phrase
    assert "https://github.com/Err0ric/lure/blob/main/SECURITY.md" in template


DOCKERFILE = REPO / "Dockerfile"
FROM_RE = re.compile(r"^FROM python:3\.12-slim-trixie@sha256:[0-9a-f]{64}( AS \w+)?$", re.MULTILINE)
SECRET_NAME_RE = re.compile(r"(KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)", re.IGNORECASE)


def _instructions():
    text = re.sub(r"\\\n\s*", " ", DOCKERFILE.read_text(encoding="utf-8"))
    return [line.strip() for line in text.splitlines()
            if line.strip() and not line.strip().startswith("#")]


def test_every_base_image_is_pinned_to_one_digest():
    froms = [i for i in _instructions() if i.startswith("FROM ")]
    assert len(froms) == 2 and all(FROM_RE.match(f) for f in froms)
    assert len({f.split("@")[1].split()[0] for f in froms}) == 1


def test_the_image_runs_as_a_non_root_user():
    users = [i for i in _instructions() if i.startswith("USER ")]
    assert users, "no USER"
    final = users[-1].split()[1]
    assert final.split(":")[0] not in ("root", "0")
    # The last USER comes after every RUN, so nothing in the final image runs as root later.
    lines = _instructions()
    assert lines.index(users[-1]) > max(i for i, line in enumerate(lines)
                                        if line.startswith("RUN "))
    assert lines[-2:] == ['ENTRYPOINT ["lure"]', 'CMD ["--help"]']


def test_no_secret_is_baked_into_the_image():
    for line in _instructions():
        if line.startswith(("ENV ", "ARG ")):
            names = re.findall(r"(\w+)=", line) or [line.split()[1]]
            assert not any(SECRET_NAME_RE.search(n) for n in names), line
        if line.startswith(("COPY ", "ADD ")):
            assert ".env" not in line and "vetting" not in line and "results" not in line, line
            assert not line.startswith("ADD "), "use COPY; ADD can fetch URLs"
    ignore = (REPO / ".dockerignore").read_text().splitlines()
    for entry in (".env", ".env.*", "results/", "vetting/", "profiles/*", "!profiles/example-*.yaml",
                  "*.duckdb", ".git/"):
        assert entry in ignore, entry


def test_the_image_copies_only_example_profiles_and_the_package_data_it_needs():
    copies = [i for i in _instructions() if i.startswith("COPY ")]
    assert "COPY profiles/example-*.yaml ./profiles/" in copies
    ignore = (REPO / ".dockerignore").read_text().splitlines()
    # *.md is ignored, but the package's own Markdown data (rubric, taxonomy notes) is kept.
    assert "*.md" in ignore and "!lure/**/*.md" in ignore


def test_the_container_guide_commands_are_ones_the_cli_accepts():
    import shlex

    from lure.cli import build_parser

    guide = (REPO / "docs" / "container.md").read_text(encoding="utf-8")
    parser = build_parser()
    found = 0
    for block in re.findall(r"```bash\n(.*?)```", guide, re.DOTALL):
        for command in re.sub(r"\\\n\s*", " ", block).splitlines():
            if not command.startswith("docker run"):
                continue
            words = shlex.split(command.replace('"$PWD', '"/x'))
            image = next(i for i, w in enumerate(words) if w.startswith("lure:"))
            parser.parse_args(words[image + 1:])
            found += 1
    assert found >= 5


AGENT_DOCKERFILE = REPO / "docker" / "agent.Dockerfile"


def _agent_instructions():
    text = re.sub(r"\\\n\s*", " ", AGENT_DOCKERFILE.read_text(encoding="utf-8"))
    return [line.strip() for line in text.splitlines()
            if line.strip() and not line.strip().startswith("#")]


def test_the_reference_agent_image_uses_the_same_pinned_base():
    froms = [i for i in _instructions() + _agent_instructions() if i.startswith("FROM ")]
    assert len(froms) == 3 and all(FROM_RE.match(f) for f in froms)
    assert len({f.split("@")[1].split()[0] for f in froms}) == 1


def test_the_reference_agent_image_is_ours_non_root_and_without_pip():
    lines = _agent_instructions()
    copies = [i for i in lines if i.startswith(("COPY ", "ADD "))]
    # Only Lure's own reference agent and decoy, nothing fetched.
    assert copies == [("COPY lure/sandbox/refagent/agent.py lure/sandbox/refagent/decoy.py "
                      "/opt/lure/")]
    users = [i for i in lines if i.startswith("USER ")]
    assert users and users[-1] == "USER 10001:10001"
    assert lines.index(users[-1]) > max(i for i, line in enumerate(lines)
                                        if line.startswith("RUN "))
    run = " ".join(i for i in lines if i.startswith("RUN "))
    assert "pip uninstall -y -q pip" in run
    for decoy in ("npm", "npx", "pip", "pip3", "curl", "wget", "git"):
        assert decoy in run
    assert "ENV PATH=/opt/lure/decoys:" in " ".join(lines)
    assert not any(SECRET_NAME_RE.search(i) for i in lines if i.startswith(("ENV ", "ARG ")))


def test_the_sandbox_guide_commands_are_ones_the_cli_accepts():
    import shlex

    from lure.cli import build_parser

    guide = (REPO / "docs" / "container.md").read_text(encoding="utf-8")
    parser = build_parser()
    found = 0
    for block in re.findall(r"```bash\n(.*?)```", guide, re.DOTALL):
        for command in re.sub(r"\\\n\s*", " ", block).splitlines():
            command = command.split("#")[0].strip()
            if command.startswith("lure sandbox"):
                parser.parse_args(shlex.split(command)[1:])
                found += 1
    assert found == 4


def test_secret_scanning_is_pinned_and_fails_on_findings():
    import yaml
    hooks = yaml.safe_load((REPO / ".pre-commit-config.yaml").read_text())
    [repo] = hooks["repos"]
    assert repo["repo"] == "https://github.com/gitleaks/gitleaks"
    assert re.fullmatch(r"[0-9a-f]{40}", repo["rev"]) and repo["hooks"] == [{"id": "gitleaks"}]
    ci = yaml.safe_load((REPO / ".github" / "workflows" / "ci.yml").read_text())
    steps = ci["jobs"]["gitleaks"]["steps"]
    action = next(s for s in steps if "gitleaks-action" in s.get("uses", ""))
    assert re.fullmatch(r"gitleaks/gitleaks-action@[0-9a-f]{40}", action["uses"])
    # Nothing turns a finding into a pass.
    assert "continue-on-error" not in action and "continue-on-error" not in ci["jobs"]["gitleaks"]
    # Every allowed finding is a deliberate test value with an inline allow.
    for line in (REPO / ".gitleaksignore").read_text().splitlines():
        if line and not line.startswith("#"):
            commit, path, _rule, _line = line.split(":")
            assert re.fullmatch(r"[0-9a-f]{40}", commit) and path.startswith("tests/")
            assert "# gitleaks:allow" in (REPO / path).read_text()
