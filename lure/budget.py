"""Spend so far in a batch, and the --max-cost stop.

Every model call reports its tokens; the prices file turns them into an
estimate. Attacker, target and judge spend all count toward the cap.

The cap is checked before each attempt (a target run, plus the attacker's
rewrite when adaptive): if spend so far plus the average attempt so far
would pass it, the batch stops there instead of going over by a whole run.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from lure.prices import Prices, PricesError

ROLES = ("attacker", "target", "judge")


@dataclass
class Budget:
    prices: Prices
    max_cost: float | None = None
    spent: dict[str, float] = field(default_factory=lambda: dict.fromkeys(ROLES, 0.0))
    attempts: int = 0
    # Set once the cap stops the batch.
    stopped: bool = False

    def check_models(self, models: list[str]) -> None:
        """Every model the batch will call must have a price, before any call."""
        missing = [m for m in models if self.prices.rates(m) is None]
        if missing:
            raise PricesError(f"{self.prices.source}: no price for {', '.join(missing)}")

    def charge(self, role: str, model: str, usage: dict[str, int],
               requests: list[dict[str, int]] | None = None) -> float:
        """Charge a role. With `requests`, each model request is priced on
        its own (a long-context tier applies per request)."""
        cost = self.prices.cost(model, usage, requests=requests)
        if cost is None:
            raise PricesError(f"{self.prices.source}: no price for {model} "
                              f"(or for one of {', '.join(sorted(usage))})")
        self.spent[role] += cost
        return cost

    def charge_attempt(self, target: str, usage: dict[str, int],
                       judge_llm: dict | None = None,
                       requests: list[dict[str, int]] | None = None) -> dict[str, float]:
        """Charge one target run and its LLM judge call, if any. Counts as
        one attempt for the average. Returns the costs by role."""
        costs = {"target": self.charge("target", target, usage, requests)}
        if judge_llm and judge_llm.get("usage"):
            costs["judge"] = self.charge("judge", judge_llm["model"], judge_llm["usage"],
                                         [judge_llm["usage"]])
        self.attempts += 1
        return costs

    @property
    def total(self) -> float:
        return sum(self.spent.values())

    def allows_another(self) -> bool:
        """False once spend so far plus one average attempt would pass the
        cap. Marks the budget stopped."""
        if self.max_cost is None:
            return True
        average = self.total / self.attempts if self.attempts else 0.0
        if self.total + average > self.max_cost:
            self.stopped = True
        return not self.stopped

    def line(self) -> str:
        parts = ", ".join(f"{role} ${self.spent[role]:.2f}" for role in ROLES)
        return f"${self.total:.2f} ({parts})"
