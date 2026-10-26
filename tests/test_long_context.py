"""Long-context price tiers (v1.14.3): Haiku 5.5 charges 5x for a request
whose prompt is over 100,000 tokens, per Anthropic's pricing page, checked
2026-10-25. Priced per request, cache reads and writes in the prompt."""

from pathlib import Path

import pytest

from lure.budget import Budget
from lure.prices import PricesError, load_prices

REPO = Path(__file__).resolve().parent.parent
PRICES = load_prices(REPO / "prices.example.yaml")
HAIKU = "claude-haiku-5-5"


def test_the_example_table_has_haikus_long_context_tier():
    above, rates = PRICES.tier(HAIKU)
    base = PRICES.rates(HAIKU)
    assert above == 100_000
    for k in ("input", "output", "cache_write", "cache_read"):
        assert rates[k] == pytest.approx(5 * base[k]), k
    assert PRICES.tier("anthropic:" + HAIKU) == (above, rates)
    assert PRICES.tier("claude-sonnet-5-5") is None


@pytest.mark.parametrize("usage, expected", [
    ({"input_tokens": 100_000, "output_tokens": 1_000}, 100_000 * 0.10 + 1_000 * 0.50),
    ({"input_tokens": 100_001, "output_tokens": 1_000}, 100_001 * 0.50 + 1_000 * 2.50),
    # Cache reads and writes count toward the prompt.
    ({"input_tokens": 10_000, "cache_read_input_tokens": 95_000, "output_tokens": 100},
     10_000 * 0.50 + 95_000 * 0.05 + 100 * 2.50),
    ({"input_tokens": 1_000, "cache_creation_input_tokens": 50_000, "output_tokens": 100},
     1_000 * 0.10 + 50_000 * 0.125 + 100 * 0.50),
])
def test_one_request(usage, expected):
    assert PRICES.request_cost(HAIKU, usage) == pytest.approx(expected / 1e6)


def test_each_request_is_priced_on_its_own():
    small = {"input_tokens": 60_000, "output_tokens": 500}
    big = {"input_tokens": 120_000, "output_tokens": 500}
    total = {"input_tokens": 180_000, "output_tokens": 1_000}
    per_request = PRICES.cost(HAIKU, total, requests=[small, big])
    assert per_request == pytest.approx((60_000 * 0.10 + 500 * 0.50
                                         + 120_000 * 0.50 + 500 * 2.50) / 1e6)
    # Two requests under the threshold stay at base rates, though their
    # total is over it.
    two_small = PRICES.cost(HAIKU, total, requests=[small, {**small, "input_tokens": 120_000 - 1}])
    assert two_small < PRICES.cost(HAIKU, total)


def test_totals_alone_are_an_upper_bound():
    """A record without usage_requests (before 1.14.3): over the threshold in
    total, the tier is charged on everything."""
    total = {"input_tokens": 180_000, "output_tokens": 1_000}
    assert PRICES.cost(HAIKU, total) == pytest.approx((180_000 * 0.50 + 1_000 * 2.50) / 1e6)


def test_the_budget_uses_the_tier():
    budget = Budget(PRICES, max_cost=1.0)
    big = {"input_tokens": 150_000, "output_tokens": 2_000}
    cost = budget.charge("target", HAIKU, big, [big])
    assert cost == pytest.approx((150_000 * 0.50 + 2_000 * 2.50) / 1e6)
    assert budget.total == pytest.approx(cost)


@pytest.mark.parametrize("tier, message", [
    ({"input": 0.5}, "needs above"),
    ({"above": 0, "input": 0.5}, "whole number"),
    ({"above": 100000}, "rates must be some of"),
    ({"above": 100000, "inputs": 0.5}, "rates must be some of"),
    ({"above": 100000, "input": -1}, "at least 0"),
])
def test_bad_tiers(tmp_path, tier, message):
    import yaml
    path = tmp_path / "prices.yaml"
    path.write_text(yaml.safe_dump({"models": {HAIKU: {"input": 0.1, "output": 0.5,
                                                       "long_context": tier}}}))
    with pytest.raises(PricesError, match=message):
        load_prices(path)


def test_a_run_records_each_request_and_lure_run_charges_per_request():
    from lure.attacks import load_attack
    from lure.runner import run_attack
    from tests.fakes import ScriptedAdapter, call, say
    attack = load_attack(REPO / "attacks" / "indirect_prompt_injection" / "lure-ipi-001.yaml")
    from dataclasses import replace
    first = replace(call("read_inbox"), usage={"input_tokens": 60_000, "output_tokens": 200})
    second = replace(say("Two invoices; one asks to forward them. I did not."),
                     usage={"input_tokens": 120_000, "output_tokens": 300})
    result = run_attack(attack, ScriptedAdapter(first, second))
    assert result.usage_requests == [first.usage, second.usage]
    assert result.to_dict()["usage_requests"] == [first.usage, second.usage]
    budget = Budget(PRICES, max_cost=1.0)
    costs = budget.charge_attempt(f"anthropic:{HAIKU}", result.usage, None,
                                  result.usage_requests)
    assert costs["target"] == pytest.approx((60_000 * 0.10 + 200 * 0.50
                                             + 120_000 * 0.50 + 300 * 2.50) / 1e6)


def test_sandbox_max_cost_prices_each_request_with_the_tier():
    """Two requests: the first under 100,000 tokens ($0.0061), the second over
    it ($0.0625). The cap of $0.05 is passed by the second, at 5x."""
    from tests.test_sandbox import FakeSandbox, _budgeted, _lines, _usage
    lines = _lines(_usage(60_000, 200),
                   {"lure": "call", "tool": "list_files", "args": {}, "result": {}},
                   _usage(120_000, 1_000), {"lure": "reply", "text": "Done."})
    fake = FakeSandbox(lines, [])
    result, _budget = _budgeted(fake, cap=0.05)
    assert fake.stopped_after == 3 and result.stop == "max_cost"
    assert result.cost["target"] == pytest.approx((60_000 * 0.10 + 200 * 0.50
                                                   + 120_000 * 0.50 + 1_000 * 2.50) / 1e6)
    assert result.usage_requests == [{"input_tokens": 60_000, "output_tokens": 200},
                                     {"input_tokens": 120_000, "output_tokens": 1_000}]
    # At base rates the same tokens would not pass the cap.
    assert (180_000 * 0.10 + 1_200 * 0.50) / 1e6 < 0.05
