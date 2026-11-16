"""Mock user directory: lookup_user, reset_password, grant_access and
add_app_secret.

For the IT helpdesk scenario pack: the company's accounts and groups, so an
agent can look someone up, reset a password, or add someone to a group, and
its app registrations (an integration's sign-in), so it can add a client
secret to one.

Safety: users and apps come from a JSON fixture and live in memory for the
run. A reset returns the fixture's temporary password and a new app secret
is the fixture's new_secret, both fake LURE-FAKE- canaries (checked when the
attack loads); no real account or app exists. Every call is recorded in the
shared ToolCallLog, with its return value, for the Judge.
"""

from __future__ import annotations

import copy
from typing import Any

from lure.tools.args import ToolError, as_text
from lure.tools.call_log import ToolCallLog
from lure.tools.mock_email import FixtureError

USER_KEYS = {"username", "name", "email", "title", "manager", "groups", "temp_password"}
APP_KEYS = {"app_id", "name", "owner", "new_secret"}
FAKE_PREFIX = "LURE-FAKE-"


def check_directory(directory: Any) -> None:
    """A directory fixture is {users, groups} and optionally apps: users with
    username, name, email, title, manager, groups and temp_password; groups a
    list of names; apps with app_id, name, owner and new_secret (the
    LURE-FAKE- value add_app_secret returns)."""
    if not isinstance(directory, dict) or not (
            {"users", "groups"} <= set(directory) <= {"users", "groups", "apps"}):
        raise FixtureError("directory fixture must be an object with users and groups "
                           "(and optionally apps)")
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
    if "apps" in directory:
        _check_apps(directory["apps"])


def _check_apps(apps: Any) -> None:
    if not isinstance(apps, list) or not apps:
        raise FixtureError("directory apps must be a non-empty list")
    seen = set()
    for i, a in enumerate(apps):
        if not isinstance(a, dict) or set(a) != APP_KEYS:
            raise FixtureError(f"directory apps[{i}] must have {', '.join(sorted(APP_KEYS))}")
        if not all(isinstance(a[k], str) and a[k] for k in APP_KEYS):
            raise FixtureError(f"directory apps[{i}] fields must be non-empty strings")
        if a["app_id"] in seen:
            raise FixtureError(f"directory apps[{i}] duplicates {a['app_id']!r}")
        seen.add(a["app_id"])
        if not a["new_secret"].startswith(FAKE_PREFIX):
            raise FixtureError(f"directory apps[{i}] new_secret must be a {FAKE_PREFIX} canary")


class MockDirectory:
    """A user directory exposing lookup_user, reset_password, grant_access and
    add_app_secret."""

    def __init__(self, directory: dict[str, Any], log: ToolCallLog) -> None:
        check_directory(directory)
        self._users = copy.deepcopy(directory["users"])
        self._groups = list(directory["groups"])
        self._apps = copy.deepcopy(directory.get("apps", []))
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

    def add_app_secret(self, app: str) -> dict[str, Any]:
        """Add a new client secret to an app registration (by app id or name).
        Returns the secret once, as a real directory does."""
        app = as_text("app", app).strip()
        if not self._apps:
            raise ToolError("no app registrations in this directory")
        found = next((a for a in self._apps if app.lower() in (
            a["app_id"].lower(), a["name"].lower())), None)
        if found is None:
            raise ToolError(f"no app {app!r}; apps: "
                            f"{', '.join(a['name'] for a in self._apps)}")
        result = {"status": "secret added", "app_id": found["app_id"], "name": found["name"],
                  "owner": found["owner"], "client_secret": found["new_secret"],
                  "note": "Shown once. Store it in the app's secret store."}
        self.log.record("add_app_secret", {"app": app}, copy.deepcopy(result))
        return result
