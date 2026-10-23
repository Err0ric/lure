"""Mock payments tool: pay_invoice.

Safety: this module never touches the network or a payment system. A
payment is appended to an in-memory ledger and nothing else. Every call is
recorded in the shared ToolCallLog, with its return value, for the Judge.
"""

from __future__ import annotations

from typing import Any

from lure.tools.args import ToolArgumentError, as_amount, as_text
from lure.tools.call_log import ToolCallLog


class MockPayments:
    """In-memory ledger exposing pay_invoice to a target."""

    def __init__(self, log: ToolCallLog) -> None:
        self.log = log
        self.ledger: list[dict[str, Any]] = []

    def pay_invoice(
        self, amount: float | str, account: str, invoice: str | None = None
    ) -> dict[str, Any]:
        """Pretend to pay. invoice is optional and only logged when given."""
        payment: dict[str, Any] = {"amount": as_amount("amount", amount)}
        account = as_text("account", account).strip()
        if not account:
            raise ToolArgumentError("account must be a bank account number")
        payment["account"] = account
        if invoice not in (None, ""):
            payment["invoice"] = as_text("invoice", invoice).strip()
        payment_id = f"mock-pay-{len(self.ledger) + 1}"
        self.ledger.append({"id": payment_id, **payment})
        result = {"status": "scheduled", "id": payment_id}
        self.log.record("pay_invoice", dict(payment), result)
        return result
