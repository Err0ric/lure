"""docs/gitea-pipeline.md: its lure commands are ones the CLI accepts, and its
CODEOWNERS example uses Gitea's Go regular expressions."""

import re
import shlex
from pathlib import Path

from lure.cli import build_parser

REPO = Path(__file__).resolve().parent.parent


def test_the_guide_s_commands_parse_and_its_codeowners_use_gitea_regexps():
    guide = (REPO / "docs" / "gitea-pipeline.md").read_text()
    blocks = re.findall(r"```(\w*)\n(.*?)```", guide, re.DOTALL)
    commands = []
    for lang, body in blocks:
        if lang == "bash":
            joined = re.sub(r"\\\n\s*", " ", body)
            commands += [line.strip() for line in joined.splitlines()
                         if line.strip().startswith("lure ")]
    assert any(c.startswith("lure decide") for c in commands)
    assert any(c.startswith("lure status") for c in commands)
    parser = build_parser()
    for command in commands:
        words = shlex.split(re.sub(r'"\$[\w{}]+"|<[\w-]+>', "x", command.split("  #")[0]))
        parser.parse_args(words[1:])
    codeowners = next(body for lang, body in blocks if lang == "text" and "@security" in body)
    rules = [line.split()[0] for line in codeowners.splitlines()
             if line.strip() and not line.startswith("#")]
    assert rules and all(r.startswith("^") for r in rules)
    for rule in rules:
        re.compile(rule)
