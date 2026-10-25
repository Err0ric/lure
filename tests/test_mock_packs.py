"""Mocks for the customer support and IT helpdesk packs: tickets, customers
and the user directory. In memory only; nothing is sent, refunded or reset."""

import pytest

from lure.adapters.base import ToolCallRequest
from lure.report.approval import CAPABILITY, GROUPS
from lure.tools import GATABLE_TOOLS, KNOWN_TOOLS, READ_TOOLS
from lure.tools.args import ToolError
from lure.tools.call_log import ToolCallLog
from lure.tools.mock_customers import MockCustomers, check_customers
from lure.tools.mock_directory import MockDirectory, check_directory
from lure.tools.mock_email import FixtureError
from lure.tools.mock_tickets import MockTickets, check_tickets
from lure.tools.registry import TOOL_SPECS, build_toolbox

TICKETS = [{"id": "T-1", "from": "dana@home-mail.example", "subject": "Refund", "body": "Hi"},
           {"id": "T-2", "from": "x@home-mail.example", "subject": "Done", "body": "Thanks",
            "status": "closed"}]
CUSTOMERS = [{"id": "C-1", "name": "Dana Reyes", "email": "dana@home-mail.example",
              "orders": [{"order_id": "SO-1", "total": "84.00", "card_last4": "4417"}]}]
DIRECTORY = {"groups": ["staff", "finance-admins"],
             "users": [{"username": "mhale", "name": "Morgan Hale", "email": "mhale@corp.example",
                        "title": "CFO", "manager": "board", "groups": ["staff"],
                        "temp_password": "LURE-FAKE-TEMP-PW-7Q2M"}]}


def test_tickets_list_open_ones_and_reply_to_the_requester():
    log = ToolCallLog()
    desk = MockTickets(TICKETS, log)
    assert [t["id"] for t in desk.list_tickets()] == ["T-1"]
    assert desk.reply_ticket("T-1", "Refund issued.") == {
        "status": "replied", "ticket_id": "T-1", "to": "dana@home-mail.example"}
    with pytest.raises(ToolError, match="no ticket"):
        desk.reply_ticket("T-9", "x")
    assert [c.tool for c in log.calls] == ["list_tickets", "reply_ticket"]


def test_customers_lookup_update_and_refund_in_memory():
    log = ToolCallLog()
    store = MockCustomers(CUSTOMERS, log)
    assert store.lookup_customer("SO-1")["id"] == "C-1"
    assert store.update_customer("C-1", "email", "new@else.example")["old"] == (
        "dana@home-mail.example")
    assert store.lookup_customer("new@else.example")["id"] == "C-1"
    refund = store.issue_refund("SO-1", "$84.00", "4417")
    assert refund == {"status": "refunded", "refund_id": "RF-0001", "order_id": "SO-1",
                      "amount": 84.0, "card_last4": "4417"}
    with pytest.raises(ToolError, match="card_last4"):
        store.issue_refund("SO-1", 10, "44")
    with pytest.raises(ToolError, match="field must be one of"):
        store.update_customer("C-1", "password", "x")
    assert CUSTOMERS[0]["email"] == "dana@home-mail.example"


def test_directory_lookup_hides_the_temp_password_and_reset_returns_it():
    log = ToolCallLog()
    directory = MockDirectory(DIRECTORY, log)
    assert "temp_password" not in directory.lookup_user("Morgan Hale")
    assert directory.reset_password("mhale")["temporary_password"] == "LURE-FAKE-TEMP-PW-7Q2M"
    assert directory.grant_access("mhale", "finance-admins")["status"] == "added"
    assert directory.grant_access("mhale", "finance-admins")["status"] == "already a member"
    with pytest.raises(ToolError, match="no group"):
        directory.grant_access("mhale", "root")
    assert DIRECTORY["users"][0]["groups"] == ["staff"]


@pytest.mark.parametrize("check, bad", [
    (check_tickets, []),
    (check_tickets, [TICKETS[0], TICKETS[0]]),
    (check_customers, [{**CUSTOMERS[0], "orders": [{"order_id": "1", "total": "1",
                                                    "card_last4": "41"}]}]),
    (check_directory, {"users": DIRECTORY["users"], "groups": []}),
])
def test_bad_fixtures_are_rejected(check, bad):
    with pytest.raises(FixtureError):
        check(bad)


def test_every_tool_is_wired_and_named_on_the_approval_page():
    assert set(TOOL_SPECS) == KNOWN_TOOLS
    assert set(CAPABILITY) == KNOWN_TOOLS
    assert {g for g, _ in CAPABILITY.values()} <= set(GROUPS)
    assert {"list_tickets", "lookup_customer", "lookup_user"} <= set(READ_TOOLS)
    assert {"reply_ticket", "issue_refund", "update_customer", "reset_password",
            "grant_access"} <= GATABLE_TOOLS


def test_toolbox_wires_the_pack_tools_and_gates_them():
    log = ToolCallLog()
    box = build_toolbox(["list_tickets", "lookup_user", "reset_password"],
                        {"tickets": TICKETS, "directory": DIRECTORY}, log,
                        gated=frozenset({"reset_password"}), confirm=lambda tool, args: False)
    result = box.run(ToolCallRequest("c1", "reset_password", {"username": "mhale"}))
    assert "did not confirm" in result.content
    assert "LURE-FAKE" not in result.content
    assert log.calls[0].gate == "declined"
