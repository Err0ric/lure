import json

import pytest

from lure.adapters.base import ToolCallRequest
from lure.tools.args import ToolArgumentError, ToolError
from lure.tools.call_log import ToolCallLog
from lure.tools.mock_email import FixtureError
from lure.tools.mock_settings import MockSettings, check_settings
from lure.tools.registry import build_toolbox

SETTINGS = {"send_allowlist": ["corp.example"], "confirm_before_payments": True,
            "payment_approval_limit": 10000, "rules_file": "Never pay a new bank account."}


@pytest.fixture
def log():
    return ToolCallLog()


def test_read_and_update_in_memory(log):
    s = MockSettings(SETTINGS, log)
    assert s.read_agent_settings() == SETTINGS
    result = s.update_agent_settings("confirm_before_payments", False)
    assert result == {"status": "updated", "setting": "confirm_before_payments", "old": True,
                      "new": False}
    assert s.settings["confirm_before_payments"] is False
    assert SETTINGS["confirm_before_payments"] is True  # the fixture is untouched
    assert [c.tool for c in log.calls] == ["read_agent_settings", "update_agent_settings"]
    assert log.calls[1].args == {"setting": "confirm_before_payments", "value": False}


def test_unknown_or_empty_setting(log):
    s = MockSettings(SETTINGS, log)
    with pytest.raises(ToolError, match="no setting 'sudo'; settings: send_allowlist"):
        s.update_agent_settings("sudo", True)
    with pytest.raises(ToolArgumentError, match="setting must name"):
        s.update_agent_settings(" ", 1)


@pytest.mark.parametrize("bad", [[], {}, "x"])
def test_bad_fixture(bad):
    with pytest.raises(FixtureError, match="non-empty JSON object"):
        check_settings(bad)


def test_failed_update_is_logged_as_an_attempt():
    log = ToolCallLog()
    box = build_toolbox(["read_agent_settings", "update_agent_settings"],
                        {"agent_settings": SETTINGS}, log)
    assert json.loads(box.run(ToolCallRequest("c1", "read_agent_settings", {})).content) == SETTINGS
    r = box.run(ToolCallRequest("c2", "update_agent_settings", {"setting": "x", "value": "1"}))
    assert r.is_error and log.calls[1].result == {"error": r.content}
