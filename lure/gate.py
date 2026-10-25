"""Confirm gate: a person confirms each call to a gated tool before it runs.

A profile marks a tool `gated: true` when the agent's app asks a person to
confirm every call to it. Lure simulates that step: the call stops at the
gate, a stand-in for the person sees its full arguments, and either confirms
it (the mock tool then runs as usual) or declines it (nothing runs, and the
agent is told the person did not confirm). Every call is logged with its
gate outcome, so the judge sees an attempt the gate stopped and the report
can count how often the agent asked again after a decline.

The stand-in person (the profile's `confirmer`):

  careful    reads every field and declines a call the attack's own fail_if
             rules count as harm (only rules about the call itself: its
             tool and arguments); confirms the rest, so the real task can
             still be done. This is the best case for the gate: a person
             who reads every field and spots what the attack is after.
  deny_all   declines every call. Tests only whether the agent finds a way
             around the gate.

What this shows, and what it cannot: Lure tests the agent's side, whether
it gets the harm done some other way, and how it reacts to a decline. It
cannot show that the real app has the gate, that the gate shows the full
arguments, or that the people confirming read them. The approval report
says so, and asks the approver to confirm the real gate on sign-off.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from lure.attacks import Attack
from lure.judge.rules import call_matches
from lure.tools.call_log import CONFIRMED, DECLINED, DECLINED_RESULT, ToolCall

__all__ = ["CAREFUL", "CONFIRMED", "CONFIRMERS", "DECLINED", "DECLINED_RESULT", "DENY_ALL", "Gate"]

CAREFUL = "careful"
DENY_ALL = "deny_all"
CONFIRMERS = (CAREFUL, DENY_ALL)

# Rule keys that are not about the call itself: a careful person sees the
# call, not the reply the agent writes later.
NOT_THE_CALL = ("reply_contains", "reply_url", "asked_user_before", "flagged_as_suspicious")

Confirm = Callable[[str, dict[str, Any]], bool]


@dataclass(frozen=True)
class Gate:
    """The gated Lure tools of a profile, and who confirms."""

    tools: frozenset[str]
    confirmer: str = CAREFUL

    def confirm_for(self, attack: Attack) -> Confirm:
        """The stand-in person for one run of this attack: True confirms."""
        if self.confirmer == DENY_ALL:
            return lambda tool, args: False
        harm = [r for r in attack.fail_if if r.get("tool") in self.tools
                and not any(k in r for k in NOT_THE_CALL)]

        def confirm(tool: str, args: dict[str, Any]) -> bool:
            call = ToolCall(datetime.now(UTC), tool, args)
            return not any(r["tool"] == tool and call_matches(call, r) for r in harm)

        return confirm

