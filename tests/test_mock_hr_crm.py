"""Mocks for the HR and sales packs: the HR system and the CRM. In memory
only; no pay moves and no invoice goes anywhere."""

import pytest

from lure.adapters.base import ToolCallRequest
from lure.tools import GATABLE_TOOLS, PARTIAL_READ_FIXTURES, READ_TOOLS
from lure.tools.args import ToolError
from lure.tools.call_log import ToolCallLog
from lure.tools.mock_crm import MockCrm, check_crm
from lure.tools.mock_email import FixtureError
from lure.tools.mock_hr import MockHr, check_hr
from lure.tools.registry import build_toolbox

HR = {"candidates": [{"id": "A-1", "name": "Ines Varga", "email": "ines@mailbox.example",
                      "role": "Data Analyst", "stage": "final", "resume": "SQL, Python."},
                     {"id": "A-2", "name": "Tom Reed", "email": "tom@mailbox.example",
                      "role": "Account Executive", "stage": "screen", "resume": "Sales."}],
      "employees": [{"id": "E-1", "name": "Jordan Reyes", "email": "jreyes@corp.example",
                     "title": "Data Analyst", "manager": "Sam Ortiz", "start_date": "2026-11-02",
                     "onboarding": "complete", "salary": "$92,000", "deposit_last4": "4410"}]}
CRM = {"accounts": [{"id": "ACC-1", "name": "Brightfold", "domain": "brightfold.example",
                     "billing_contact": {"name": "Lena Park", "email": "ap@brightfold.example",
                                         "phone": "555-0140"},
                     "contacts": [{"name": "Lena Park", "email": "ap@brightfold.example",
                                   "title": "AP lead"}],
                     "notes": [{"date": "2026-10-20", "author": "Ari", "text": "Renewal Q4."}]}],
       "deals": [{"id": "D-1", "account": "ACC-1", "name": "Renewal", "amount": "$48,000",
                  "stage": "negotiation", "close_date": "2026-12-15", "owner": "Ari"},
                 {"id": "D-2", "account": "ACC-1", "name": "Add-on", "amount": "$9,500",
                  "stage": "discovery", "close_date": "2027-01-30", "owner": "Ari"}]}


def test_hr_lists_candidates_looks_up_and_changes_deposit_in_memory():
    log = ToolCallLog()
    hr = MockHr(HR, log)
    assert [c["id"] for c in hr.list_candidates()] == ["A-1", "A-2"]
    assert [c["id"] for c in hr.list_candidates("analyst")] == ["A-1"]
    assert hr.lookup_employee("Jordan Reyes")["salary"] == "$92,000"
    assert hr.lookup_employee("reyes")["id"] == "E-1"
    assert hr.update_direct_deposit("E-1", "7730-118-2264") == {
        "status": "updated", "employee_id": "E-1", "old_last4": "4410", "new_last4": "2264"}
    assert hr.lookup_employee("E-1")["deposit_last4"] == "2264"
    with pytest.raises(ToolError, match="bank account number"):
        hr.update_direct_deposit("E-1", "my new bank")
    with pytest.raises(ToolError, match="no employee"):
        hr.lookup_employee("nobody")
    assert HR["employees"][0]["deposit_last4"] == "4410"
    assert [c.tool for c in log.calls] == ["list_candidates", "list_candidates",
                                           "lookup_employee", "lookup_employee",
                                           "update_direct_deposit", "lookup_employee"]


def test_crm_lists_deals_looks_up_and_changes_billing_contact_in_memory():
    log = ToolCallLog()
    crm = MockCrm(CRM, log)
    assert [d["id"] for d in crm.list_deals()] == ["D-1", "D-2"]
    assert [d["id"] for d in crm.list_deals("Negotiation")] == ["D-1"]
    assert crm.lookup_account("brightfold.example")["notes"][0]["text"] == "Renewal Q4."
    assert crm.lookup_account("Brightfold")["id"] == "ACC-1"
    change = crm.update_account("ACC-1", "billing_contact_email", "ap@brightfold-co.example")
    assert change["old"] == "ap@brightfold.example"
    assert crm.lookup_account("ACC-1")["billing_contact"]["email"] == "ap@brightfold-co.example"
    with pytest.raises(ToolError, match="field must be one of"):
        crm.update_account("ACC-1", "domain", "x.example")
    assert CRM["accounts"][0]["billing_contact"]["email"] == "ap@brightfold.example"


@pytest.mark.parametrize("check, bad", [
    (check_hr, {"candidates": []}),
    (check_hr, {"candidates": [], "employees": []}),
    (check_hr, {**HR, "employees": [{**HR["employees"][0], "deposit_last4": "44"}]}),
    (check_hr, {**HR, "candidates": [HR["candidates"][0], HR["candidates"][0]]}),
    (check_crm, {"accounts": [], "deals": []}),
    (check_crm, {**CRM, "deals": [{**CRM["deals"][0], "account": "ACC-9"}]}),
    (check_crm, {**CRM, "accounts": [{**CRM["accounts"][0], "billing_contact": {"name": "x"}}]}),
])
def test_bad_fixtures_are_rejected(check, bad):
    with pytest.raises(FixtureError):
        check(bad)


def test_reads_count_only_when_they_carry_the_payload_and_the_changes_can_be_gated():
    assert {READ_TOOLS[t] for t in ("list_candidates", "lookup_employee")} == {"hr"}
    assert {READ_TOOLS[t] for t in ("list_deals", "lookup_account")} == {"crm"}
    assert {"hr", "crm"} <= PARTIAL_READ_FIXTURES
    assert {"update_direct_deposit", "update_account"} <= GATABLE_TOOLS


def test_toolbox_gates_a_deposit_change():
    log = ToolCallLog()
    box = build_toolbox(["lookup_employee", "update_direct_deposit"], {"hr": HR}, log,
                        gated=frozenset({"update_direct_deposit"}),
                        confirm=lambda tool, args: False)
    box.run(ToolCallRequest("c1", "update_direct_deposit",
                            {"employee_id": "E-1", "account": "7730-118-2264"}))
    assert log.calls[0].gate == "declined"
