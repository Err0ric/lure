import pytest

from lure.tools.call_log import ToolCallLog
from lure.tools.mock_email import FixtureError
from lure.tools.mock_env import MockEnv, check_env

VARS = [{"name": "ERP_BASE_URL", "value": "https://erp.corp.example"},
        {"name": "ERP_TOKEN", "value": "LURE-FAKE-erptok-41d7"},
        {"name": "CLOUD_REGION", "value": "us-test-1"}]


@pytest.fixture
def log():
    return ToolCallLog()


def test_lists_all_in_fixture_order(log):
    env = MockEnv(VARS, log)
    assert env.list_env() == VARS
    assert log.calls[0].tool == "list_env"
    assert log.calls[0].args == {"prefix": None}
    assert log.calls[0].result == VARS


@pytest.mark.parametrize("prefix", ["ERP_", "erp_", "  ERP"])
def test_prefix_any_case(log, prefix):
    assert [v["name"] for v in MockEnv(VARS, log).list_env(prefix)] == ["ERP_BASE_URL",
                                                                       "ERP_TOKEN"]


def test_never_reads_the_real_environment(log, monkeypatch):
    monkeypatch.setenv("LURE_REAL_SECRET_PROBE", "real-value-must-not-show")
    result = MockEnv(VARS, log).list_env()
    assert "LURE_REAL_SECRET_PROBE" not in str(result)
    assert MockEnv(VARS, log).list_env("LURE_REAL") == []


def test_result_is_a_copy(log):
    env = MockEnv(VARS, log)
    env.list_env()[0]["value"] = "changed"
    assert env.list_env()[0]["value"] == "https://erp.corp.example"
    assert log.calls[0].result[0]["value"] == "https://erp.corp.example"


@pytest.mark.parametrize("bad,message", [
    ({}, "JSON list"),
    ([{"name": "A"}], "name and value"),
    ([{"name": "1BAD", "value": "x"}], "variable name"),
    ([{"name": "A", "value": 3}], "value must be a string"),
    ([{"name": "A", "value": "x"}, {"name": "A", "value": "y"}], "duplicates"),
])
def test_bad_fixture(bad, message):
    with pytest.raises(FixtureError, match=message):
        check_env(bad)


def test_toolbox_wires_list_env_to_its_fixture():
    import json

    from lure.adapters.base import ToolCallRequest
    from lure.tools.registry import ToolboxError, build_toolbox

    log = ToolCallLog()
    box = build_toolbox(["list_env"], {"env": VARS}, log)
    result = box.run(ToolCallRequest("c1", "list_env", {"prefix": "CLOUD"}))
    assert json.loads(result.content) == [VARS[2]]
    assert log.calls[0].tool == "list_env"
    with pytest.raises(ToolboxError, match="needs a 'env' fixture"):
        build_toolbox(["list_env"], {}, ToolCallLog())
