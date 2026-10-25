"""Mock customer records: lookup_customer, update_customer and issue_refund.

For the customer support scenario pack: an online store's customers and
their orders, so an agent can look one up, change a contact detail, or
refund an order to a card.

Safety: customers come from a JSON fixture and live in memory for the run.
An update changes only that copy; a refund is recorded, and no money
moves. Every call is recorded in the shared ToolCallLog, with its return
value, for the Judge.
"""

from __future__ import annotations

import copy
import re
from typing import Any

from lure.tools.args import ToolArgumentError, ToolError, as_amount, as_text
from lure.tools.call_log import ToolCallLog
from lure.tools.mock_email import FixtureError

CUSTOMER_KEYS = {"id", "name", "email", "orders"}
ORDER_KEYS = {"order_id", "total", "card_last4"}
# Contact details an agent may change.
FIELDS = ("email", "phone", "shipping_address")
LAST4_RE = re.compile(r"^\d{4}$")


def check_customers(customers: Any) -> None:
    """A customers fixture is a JSON list of {id, name, email, orders}, each
    order {order_id, total, card_last4}, with optional phone and
    shipping_address."""
    if not isinstance(customers, list) or not customers:
        raise FixtureError("customers fixture must be a non-empty JSON list")
    ids, orders = set(), set()
    for i, c in enumerate(customers):
        if not isinstance(c, dict) or not CUSTOMER_KEYS <= set(c) or not set(c) <= (
                CUSTOMER_KEYS | {"phone", "shipping_address"}):
            raise FixtureError(f"customers[{i}] must have id, name, email and orders, and "
                               "optionally phone and shipping_address")
        if c["id"] in ids:
            raise FixtureError(f"customers[{i}] duplicates id {c['id']!r}")
        ids.add(c["id"])
        if not isinstance(c["orders"], list):
            raise FixtureError(f"customers[{i}].orders must be a list")
        for j, o in enumerate(c["orders"]):
            if not isinstance(o, dict) or set(o) != ORDER_KEYS:
                raise FixtureError(f"customers[{i}].orders[{j}] must have order_id, total and "
                                   "card_last4")
            if not isinstance(o["card_last4"], str) or not LAST4_RE.match(o["card_last4"]):
                raise FixtureError(f"customers[{i}].orders[{j}].card_last4 must be 4 digits")
            if o["order_id"] in orders:
                raise FixtureError(f"customers[{i}].orders[{j}] duplicates order "
                                   f"{o['order_id']!r}")
            orders.add(o["order_id"])


class MockCustomers:
    """Customer records exposing lookup_customer, update_customer and
    issue_refund."""

    def __init__(self, customers: list[dict[str, Any]], log: ToolCallLog) -> None:
        check_customers(customers)
        self._customers = copy.deepcopy(customers)
        self.log = log
        self.refunds: list[dict[str, Any]] = []

    def lookup_customer(self, query: str) -> dict[str, Any]:
        """A customer by id, email or order number."""
        query = as_text("query", query).strip().lower()
        found = next((c for c in self._customers if query in (
            c["id"].lower(), c["email"].lower(), *(o["order_id"].lower() for o in c["orders"]))),
            None)
        if found is None:
            raise ToolError(f"no customer matches {query!r}")
        result = copy.deepcopy(found)
        self.log.record("lookup_customer", {"query": query}, copy.deepcopy(result))
        return result

    def update_customer(self, customer_id: str, field: str, value: str) -> dict[str, Any]:
        """Change one contact detail on a customer's account."""
        customer_id = as_text("customer_id", customer_id).strip()
        field, value = as_text("field", field).strip(), as_text("value", value).strip()
        if field not in FIELDS:
            raise ToolArgumentError(f"field must be one of {', '.join(FIELDS)}")
        if not value:
            raise ToolArgumentError("value must be the new detail")
        customer = next((c for c in self._customers if c["id"] == customer_id), None)
        if customer is None:
            raise ToolError(f"no customer {customer_id!r}")
        old = customer.get(field)
        customer[field] = value
        result = {"status": "updated", "customer_id": customer_id, "field": field, "old": old,
                  "new": value}
        self.log.record("update_customer", {"customer_id": customer_id, "field": field,
                                            "value": value}, copy.deepcopy(result))
        return result

    def issue_refund(self, order_id: str, amount: Any, card_last4: str) -> dict[str, Any]:
        """Refund an order to a card. Recorded; no money moves."""
        order_id = as_text("order_id", order_id).strip()
        value = as_amount("amount", amount)
        card = as_text("card_last4", card_last4).strip()
        if not LAST4_RE.match(card):
            raise ToolArgumentError("card_last4 must be the card's last 4 digits")
        if not any(o["order_id"] == order_id for c in self._customers for o in c["orders"]):
            raise ToolError(f"no order {order_id!r}")
        result = {"status": "refunded", "refund_id": f"RF-{len(self.refunds) + 1:04d}",
                  "order_id": order_id, "amount": value, "card_last4": card}
        self.refunds.append(result)
        self.log.record("issue_refund", {"order_id": order_id, "amount": amount,
                                         "card_last4": card}, copy.deepcopy(result))
        return result
