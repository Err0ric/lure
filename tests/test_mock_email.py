import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from lure.tools.call_log import ToolCallLog
from lure.tools.mock_email import FixtureError, MockEmail, load_inbox

FIXED_TIME = datetime(2026, 10, 22, 12, 0, tzinfo=UTC)

INBOX = [
    {
        "from": "alice@vendor.example",
        "to": "me@corp.example",
        "subject": "Weekly update",
        "body": "Shipment arrives Friday.",
    },
    {
        "from": "billing@vendor.example",
        "to": "me@corp.example",
        "subject": "Invoice 1042",
        "body": "Invoice attached.",
    },
]


@pytest.fixture
def log():
    return ToolCallLog(clock=lambda: FIXED_TIME)


@pytest.fixture
def inbox_path(tmp_path):
    path = tmp_path / "inbox.json"
    path.write_text(json.dumps(INBOX))
    return path


@pytest.fixture
def email(inbox_path, log):
    return MockEmail.from_fixture(inbox_path, log)


# read_inbox


def test_read_inbox_returns_fixture_messages(email):
    assert email.read_inbox() == INBOX


def test_read_inbox_limit(email):
    assert email.read_inbox(limit=1) == INBOX[:1]
    assert email.read_inbox(limit=0) == []


def test_read_inbox_is_logged(email, log):
    email.read_inbox(limit=1)
    assert log.to_list() == [
        {
            "timestamp": FIXED_TIME.isoformat(),
            "tool": "read_inbox",
            "args": {"limit": 1},
            "result": INBOX[:1],
        }
    ]


def test_read_inbox_returns_copies(email):
    email.read_inbox()[0]["body"] = "tampered"
    assert email.read_inbox()[0]["body"] == INBOX[0]["body"]


def test_load_inbox_missing_file(tmp_path):
    with pytest.raises(FixtureError, match="not found"):
        load_inbox(tmp_path / "nope.json")


def test_load_inbox_invalid_json(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json")
    with pytest.raises(FixtureError, match="not valid JSON"):
        load_inbox(path)


def test_load_inbox_rejects_non_list(tmp_path):
    path = tmp_path / "obj.json"
    path.write_text(json.dumps({"messages": INBOX}))
    with pytest.raises(FixtureError, match="must be a JSON list"):
        load_inbox(path)


def test_load_inbox_rejects_missing_fields(tmp_path):
    path = tmp_path / "partial.json"
    path.write_text(json.dumps([{"from": "a@x.example"}]))
    with pytest.raises(FixtureError, match="missing fields"):
        load_inbox(path)


# send_email


def test_send_email_goes_to_outbox(email):
    result = email.send_email("bob@corp.example", "Hi", "Hello")
    assert result == {"status": "sent", "id": "mock-1"}
    assert email.outbox == [
        {"id": "mock-1", "to": ["bob@corp.example"], "subject": "Hi", "body": "Hello"}
    ]


def test_send_email_accepts_recipient_list(email):
    email.send_email(["a@corp.example", "b@evil.example"], "s", "b")
    assert email.outbox[0]["to"] == ["a@corp.example", "b@evil.example"]


def test_send_email_is_logged(email, log):
    email.send_email("billing-verify@external.example", "Invoices", "See attached")
    assert log.to_list() == [
        {
            "timestamp": FIXED_TIME.isoformat(),
            "tool": "send_email",
            "args": {
                "to": ["billing-verify@external.example"],
                "subject": "Invoices",
                "body": "See attached",
            },
            "result": {"status": "sent", "id": "mock-1"},
        }
    ]


def test_send_email_cc_and_bcc(email, log):
    email.send_email("a@corp.example", "s", "b", cc="c@corp.example",
                     bcc=["d@external.example", "e@external.example"])
    expected = {"to": ["a@corp.example"], "cc": ["c@corp.example"],
                "bcc": ["d@external.example", "e@external.example"], "subject": "s", "body": "b"}
    assert email.outbox == [{"id": "mock-1", **expected}]
    assert log.calls[0].args == expected


@pytest.mark.parametrize("empty", [None, []])
def test_send_email_omits_empty_cc_and_bcc(email, log, empty):
    email.send_email("a@corp.example", "s", "b", cc=empty, bcc=empty)
    assert set(log.calls[0].args) == {"to", "subject", "body"}


def test_send_email_bad_cc(email, log):
    from lure.tools.args import ToolArgumentError

    with pytest.raises(ToolArgumentError, match="cc must be an email address"):
        email.send_email("a@corp.example", "s", "b", cc=[3])
    assert email.outbox == [] and log.calls == []


def test_log_keeps_call_order(email, log):
    email.read_inbox()
    email.send_email("x@corp.example", "s", "b")
    email.read_inbox(limit=1)
    assert [c.tool for c in log.calls] == ["read_inbox", "send_email", "read_inbox"]
    assert len(log.calls_to("send_email")) == 1


def test_log_args_are_snapshots(email, log):
    recipients = ["a@corp.example"]
    email.send_email(recipients, "s", "b")
    recipients.append("late@evil.example")
    assert log.calls[0].args["to"] == ["a@corp.example"]


def test_log_result_is_snapshot(email, log):
    messages = email.read_inbox()
    messages[0]["body"] = "tampered"
    assert log.calls[0].result[0]["body"] == INBOX[0]["body"]


def test_module_imports_no_network_libraries():
    import lure.tools.mock_email as mod

    source = Path(mod.__file__).read_text()
    for lib in ("socket", "urllib", "http.client", "requests", "httpx", "smtplib"):
        assert f"import {lib}" not in source
