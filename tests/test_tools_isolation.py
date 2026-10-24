"""Every module in lure/tools/ is checked from its syntax tree: it may only
import from an allowlist, and may not call open, eval, exec or __import__.
A substring check misses `from socket import create_connection`; this does
not."""

import ast
from pathlib import Path

import pytest

import lure.tools

TOOLS_DIR = Path(lure.tools.__file__).parent

ALLOWED = {
    "__future__", "collections.abc", "copy", "dataclasses", "datetime",
    "decimal", "json", "posixpath", "re", "typing",
    "lure.adapters.base", "lure.tools",
}
# Loading a JSON fixture from disk is the one file read a mock may do.
EXTRA = {"mock_email.py": {"pathlib"}}
BANNED_CALLS = {"open", "eval", "exec", "compile", "__import__"}


def _imports(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name
        elif isinstance(node, ast.ImportFrom):
            yield "." * node.level + (node.module or "")


def _allowed(module: str, extra: set[str]) -> bool:
    return any(module == a or module.startswith(a + ".") for a in ALLOWED | extra)


MODULES = sorted(TOOLS_DIR.glob("*.py"))


@pytest.mark.parametrize("path", MODULES, ids=lambda p: p.name)
def test_tool_module_imports_only_allowlisted(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    extra = EXTRA.get(path.name, set())
    bad = [m for m in _imports(tree) if not _allowed(m, extra)]
    assert not bad, f"{path.name} imports {bad}; mock tools must not reach the network or disk"


@pytest.mark.parametrize("path", MODULES, ids=lambda p: p.name)
def test_tool_module_calls_no_io_builtins(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    calls = {
        n.func.id for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
    }
    assert not calls & BANNED_CALLS, f"{path.name} calls {sorted(calls & BANNED_CALLS)}"


def test_checker_catches_from_import():
    tree = ast.parse("from socket import create_connection\nimport urllib.request\n")
    assert [m for m in _imports(tree) if not _allowed(m, set())] == [
        "socket", "urllib.request",
    ]


def test_all_tool_modules_are_checked():
    names = {p.name for p in MODULES}
    assert {"mock_email.py", "mock_files.py", "mock_http.py", "mock_payments.py",
            "mock_mcp.py", "mock_memory.py", "responders.py"} <= names
