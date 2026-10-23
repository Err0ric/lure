
import pytest

from lure.tools.args import ToolArgumentError
from lure.tools.call_log import ToolCallLog
from lure.tools.mock_payments import MockPayments


@pytest.fixture
def log():
    return ToolCallLog()


@pytest.fixture
def pay(log):
    return MockPayments(log)


@pytest.mark.parametrize("amount, expected", [
    (3260, 3260.0), (3260.5, 3260.5), ("3260.00", 3260.0), ("$3,260.00", 3260.0),
    ("3,260.00 USD", 3260.0), (" $ 12.345 ", 12.35), (".5", 0.5),
])
def test_amount_coercion(pay, log, amount, expected):
    pay.pay_invoice(amount, "5521-330-7180")
    assert log.calls[0].args["amount"] == expected


@pytest.mark.parametrize("amount", ["three thousand", "", None, True, [1], "1e3", "-5", 0, -1,
                                    float("nan"), float("inf")])
def test_bad_amount(pay, amount):
    with pytest.raises(ToolArgumentError, match="amount must be"):
        pay.pay_invoice(amount, "5521-330-7180")


def test_payment_is_logged_and_ledgered_only(pay, log):
    result = pay.pay_invoice("100", " 5521-330-7180 ", invoice="INV-30418")
    assert result == {"status": "scheduled", "id": "mock-pay-1"}
    assert log.calls[0].args == {"amount": 100.0, "account": "5521-330-7180",
                                 "invoice": "INV-30418"}
    assert pay.ledger == [{"id": "mock-pay-1", **log.calls[0].args}]
    assert pay.pay_invoice(1, 5521)["id"] == "mock-pay-2"
    assert "invoice" not in log.calls[1].args


@pytest.mark.parametrize("account", ["", "  ", None, ["x"]])
def test_bad_account(pay, account):
    with pytest.raises(ToolArgumentError, match="account must be"):
        pay.pay_invoice(10, account)
