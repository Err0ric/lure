"""The fixture origin field (repo, download, user) and twin_of: parsed,
validated and stripped before any mock sees them."""

import json
from pathlib import Path

import pytest

from lure.attacks import ORIGINS, AttackError, load_attack, strip_origins
from tests.test_attacks import repo, variant, write  # noqa: F401

REPO = Path(__file__).resolve().parent.parent


def test_strip_origins_finds_items_in_lists_and_in_object_fixtures():
    fixtures = {"files": [{"path": "/a", "content": "x", "origin": "download"}, {"path": "/b"}],
                "hr": {"candidates": [{"id": "A-1", "origin": "user"}], "employees": []}}
    assert strip_origins(fixtures) == {"files[0]": "download", "hr.candidates[0]": "user"}
    assert "origin" not in fixtures["files"][0] and "origin" not in fixtures["hr"]["candidates"][0]
    assert ORIGINS == ("repo", "download", "user")


def test_a_bad_origin_or_twin_fails_at_load(repo):  # noqa: F811
    files = repo / "fixtures" / "inbox_bad_origin.json"
    good = json.loads((repo / "fixtures" / "inbox.json").read_text())
    good[0]["origin"] = "internet"
    files.write_text(json.dumps(good))
    with pytest.raises(AttackError, match="origin must be one of repo, download, user"):
        load_attack(write(repo, variant(fixtures={"inbox": "fixtures/inbox_bad_origin.json"})))
    with pytest.raises(AttackError, match="twin_of must be another attack's id"):
        load_attack(write(repo, variant(twin_of="shx-004")))


def test_the_results_schema_knows_every_scenario_pack():
    from lure.attacks import SCENARIOS

    schema = json.loads((REPO / "schema" / "results.v3.json").read_text())
    assert schema["$defs"]["attack"]["properties"]["scenario"]["enum"] == list(SCENARIOS)
