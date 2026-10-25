"""docs/writing-a-profile.md stays true to the code: the profiles it names
exist and load, and the keys it teaches are keys the loader accepts."""

import re
from pathlib import Path

from lure.profiles import OPTIONAL_KEYS, REQUIRED_KEYS, load_profile
from lure.tools import KNOWN_TOOLS

REPO = Path(__file__).resolve().parent.parent
DOC = (REPO / "docs" / "writing-a-profile.md").read_text(encoding="utf-8")
TOOL_KEYS = {"name", "description", "maps_to", "essential", "gated", "gate_shows", "gate_over"}


def test_named_profiles_exist_and_load():
    for path in set(re.findall(r"profiles/(example-[a-z-]+\.yaml)", DOC)):
        load_profile(REPO / "profiles" / path)


def test_yaml_keys_in_the_doc_are_real():
    blocks = re.findall(r"```yaml\n(.*?)```", DOC, re.DOTALL)
    keys = {m for b in blocks for m in re.findall(r"^\s*-?\s*([a-z_]+):", b, re.MULTILINE)}
    known = set(REQUIRED_KEYS) | set(OPTIONAL_KEYS) | TOOL_KEYS | {"images", "link_previews"}
    assert keys and keys <= known, keys - known


def test_mocks_in_the_doc_are_real():
    named = set(re.findall(r"\| `([a-z_]+)` \| (?:Returns|Records|Changes)", DOC))
    assert named and named <= KNOWN_TOOLS
