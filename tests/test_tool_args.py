import pytest

from lure.tools.args import ToolArgumentError, as_int, as_str_list, as_text
from lure.tools.call_log import ToolCallLog
from lure.tools.mock_email import MockEmail

INBOX = [{"from": f"v{i}@vendor.example", "to": "ap@corp.example",
          "subject": "s", "body": "b"} for i in range(3)]


@pytest.mark.parametrize("value, expected", [
    (3, 3), ("3", 3), (" 3 ", 3), ("+3", 3), (3.0, 3), ("0", 0),
])
def test_as_int_accepts_whole_numbers(value, expected):
    assert as_int("limit", value) == expected


@pytest.mark.parametrize("value", ["ten", "2.5", 2.5, "", None, True, [3], {"n": 3}])
def test_as_int_rejects(value):
    with pytest.raises(ToolArgumentError, match="limit must be a whole number"):
        as_int("limit", value)


def test_as_int_minimum():
    with pytest.raises(ToolArgumentError, match="limit must be 0 or more, got -2"):
        as_int("limit", "-2", minimum=0)


def test_as_str_list():
    assert as_str_list("to", "a@x.example") == ["a@x.example"]
    assert as_str_list("to", ["a@x.example", "b@x.example"]) == ["a@x.example", "b@x.example"]
    for bad in ([], [1], 5, None):
        with pytest.raises(ToolArgumentError, match="to must be an email address"):
            as_str_list("to", bad)


def test_as_text():
    assert as_text("subject", "hi") == "hi"
    assert as_text("subject", 42) == "42"
    with pytest.raises(ToolArgumentError, match="subject must be text"):
        as_text("subject", None)


# Through the mock tools


def test_read_inbox_string_limit():
    log = ToolCallLog()
    assert len(MockEmail(INBOX, log).read_inbox(limit="2")) == 2
    assert log.calls[0].args == {"limit": 2}


def test_read_inbox_bad_limit_not_logged_by_mock():
    log = ToolCallLog()
    with pytest.raises(ToolArgumentError):
        MockEmail(INBOX, log).read_inbox(limit="lots")
    assert log.calls == []  # the toolbox logs the failed attempt instead


def test_send_email_bad_to():
    with pytest.raises(ToolArgumentError, match="to must be"):
        MockEmail(INBOX, ToolCallLog()).send_email(to=7, subject="s", body="b")
