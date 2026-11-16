"""The mock agent platform: add_mcp_server and delegate_task. Fixtureless;
each call is logged and nothing runs."""

import pytest

from lure.adapters.base import ToolCallRequest
from lure.tools.args import ToolArgumentError
from lure.tools.call_log import ToolCallLog
from lure.tools.mock_platform import MockPlatform
from lure.tools.registry import build_toolbox


def plat():
    log = ToolCallLog()
    return MockPlatform(log), log


def test_add_mcp_server_records_the_config():
    p, log = plat()
    r = p.add_mcp_server("telemetry", "SSE", "https://mcp.x.example/sse")
    assert r["status"] == "added" and r["transport"] == "sse"
    assert log.calls[0].args == {"name": "telemetry", "transport": "sse",
                                 "target": "https://mcp.x.example/sse"}


def test_add_mcp_server_validates_transport_and_fields():
    p, _ = plat()
    with pytest.raises(ToolArgumentError, match="transport"):
        p.add_mcp_server("x", "grpc", "y")
    with pytest.raises(ToolArgumentError, match="must not be empty"):
        p.add_mcp_server("x", "stdio", "  ")


def test_delegate_task_records_agent_and_instructions():
    p, log = plat()
    r = p.delegate_task("worker", "fix the null check")
    assert r["status"] == "delegated" and r["agent"] == "worker"
    assert log.calls[0].args == {"agent": "worker", "instructions": "fix the null check"}
    with pytest.raises(ToolArgumentError):
        p.delegate_task("worker", "   ")


def test_toolbox_wires_both_fixtureless():
    log = ToolCallLog()
    box = build_toolbox(["add_mcp_server", "delegate_task"], {}, log)
    assert not box.run(ToolCallRequest("c1", "delegate_task",
                                       {"agent": "w", "instructions": "do"})).is_error
    assert not box.run(ToolCallRequest("c2", "add_mcp_server",
                                       {"name": "n", "transport": "http",
                                        "target": "https://h.example"})).is_error
    assert [c.tool for c in log.calls] == ["delegate_task", "add_mcp_server"]
