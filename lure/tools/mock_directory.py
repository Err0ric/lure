"""Mock user directory: lookup_user, reset_password and grant_access.

For the IT helpdesk scenario pack: the company's accounts and groups, so an
agent can look someone up, reset a password, or add someone to a group.

Safety: users come from a JSON fixture and live in memory for the run. A
reset returns the fixture's temporary password, a fake LURE-FAKE- canary
(checked when the attack loads); no real account exists. Every call is
recorded in the shared ToolCallLog, with its return value, for the Judge.
"""

from __future__ import annotations

import copy
from typing import Any

from lure.tools.args import ToolError, as_text
from lure.tools.call_log import ToolCallLog
from lure.tools.mock_email import FixtureError

USER_KEYS = {"username", "name", "email", "title", "manager", "groups", "temp_password"}


def check_directory(directory: Any) -> None:
    """A directory fixture is {users, groups}: users with username, name,
    email, title, manager, groups and temp_password; groups a list of names."""
    if not isinstance(directory, dict) or set(directory) != {"users", "groups"}:
        raise FixtureError("directory fixture must be an object with users and groups")
    groups = directory["groups"]
    if not isinstance(groups, list) or not all(isinstance(g, str) and g for g in groups):
        raise FixtureError("directory groups must be a list of group names")
    users = directory["users"]
    if not isinstance(users, list) or not users:
        raise FixtureError("directory users must be a non-empty list")
    seen = set()
    for i, u in enumerate(users):
        if not isinstance(u, dict) or set(u) != USER_KEYS:
            raise FixtureError(f"directory users[{i}] must have {', '.join(sorted(USER_KEYS))}")
        if u["username"] in seen:
            raise FixtureError(f"directory users[{i}] duplicates {u['username']!r}")
        seen.add(u["username"])
        if not isinstance(u["groups"], list) or not set(u["groups"]) <= set(groups):
            raise FixtureError(f"directory users[{i}] groups must be listed in groups")


class MockDirectory:
    """A user directory exposing lookup_user, reset_password and grant_access."""

    def __init__(self, directory: dict[str, Any], log: ToolCallLog) -> None:
        check_directory(directory)
        self._users = copy.deepcopy(directory["users"])
        self._groups = list(directory["groups"])
        self.log = log

    def _user(self, username: str) -> dict[str, Any]:
        found = next((u for u in self._users if u["username"] == username), None)
        if found is None:
            raise ToolError(f"no user {username!r}")
        return found

    def lookup_user(self, query: str) -> dict[str, Any]:
        """A user by username, email or full name. The temporary password is
        never shown here."""
        query = as_text("query", query).strip().lower()
        found = next((u for u in self._users if query in (
            u["username"].lower(), u["email"].lower(), u["name"].lower())), None)
        if found is None:
            raise ToolError(f"no user matches {query!r}")
        result = {k: copy.deepcopy(v) for k, v in found.items() if k != "temp_password"}
        self.log.record("lookup_user", {"query": query}, copy.deepcopy(result))
        return result

    def reset_password(self, username: str) -> dict[str, Any]:
        """Reset a user's password; returns the temporary one."""
        username = as_text("username", username).strip()
        user = self._user(username)
        result = {"status": "reset", "username": username,
                  "temporary_password": user["temp_password"],
                  "note": "The user must change it at next sign-in."}
        self.log.record("reset_password", {"username": username}, copy.deepcopy(result))
        return result

    def grant_access(self, username: str, group: str) -> dict[str, Any]:
        """Add a user to a group."""
        username, group = as_text("username", username).strip(), as_text("group", group).strip()
        user = self._user(username)
        if group not in self._groups:
            raise ToolError(f"no group {group!r}; groups: {', '.join(self._groups)}")
        added = group not in user["groups"]
        if added:
            user["groups"].append(group)
        result = {"status": "added" if added else "already a member", "username": username,
                  "group": group}
        self.log.record("grant_access", {"username": username, "group": group},
                        copy.deepcopy(result))
        return result
