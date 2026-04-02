"""Tests for AgentScanner (no LLM/network required)."""
from __future__ import annotations

import json
import pytest
from unittest.mock import MagicMock, patch

from vibee_hacker.core.agent_scanner import AgentScanner, AgentScanResult
from vibee_hacker.core.state import ScanState


def make_agent(max_iterations: int = 5) -> AgentScanner:
    """Create an AgentScanner with a mock LLM config."""
    mock_config = MagicMock()
    mock_config.is_configured = False

    with patch('vibee_hacker.core.agent_scanner.AgentScanner._register_tools'):
        agent = AgentScanner.__new__(AgentScanner)
        agent._llm_config = mock_config
        agent._timeout = 60
        agent._concurrency = 10
        agent._safe_mode = True
        agent._max_iterations = max_iterations
        agent._tracer = None
        agent.state = ScanState(max_iterations=max_iterations)
        agent._findings = []
        agent._conversation = []
    return agent


def test_agent_scanner_initializes_state():
    agent = make_agent(max_iterations=10)
    assert isinstance(agent.state, ScanState)
    assert agent.state.max_iterations == 10
    assert agent._findings == []
    assert agent._conversation == []


def test_parse_tool_call_from_code_block():
    text = '```json\n{"tool": "terminal_execute", "args": {"command": "echo hi"}}\n```'
    result = AgentScanner._parse_tool_call(text)
    assert result is not None
    assert result["tool"] == "terminal_execute"
    assert result["args"]["command"] == "echo hi"


def test_parse_tool_call_raw_json():
    text = 'Some reasoning here. {"tool": "finish", "args": {"summary": "done"}}'
    result = AgentScanner._parse_tool_call(text)
    assert result is not None
    assert result["tool"] == "finish"


def test_parse_tool_call_nested_json():
    payload = {
        "tool": "http_request",
        "args": {"url": "http://target.com", "headers": {"X-Custom": "value"}}
    }
    text = f'Reasoning...\n{json.dumps(payload)}'
    result = AgentScanner._parse_tool_call(text)
    assert result is not None
    assert result["tool"] == "http_request"


def test_parse_tool_call_returns_none_for_invalid():
    result = AgentScanner._parse_tool_call("just plain text, no JSON here")
    assert result is None


def test_format_tool_result_error_dict():
    result = AgentScanner._format_tool_result("some_tool", {"error": "Connection refused"})
    assert "ERROR" in result
    assert "Connection refused" in result


def test_format_tool_result_stdout_dict():
    result = AgentScanner._format_tool_result(
        "terminal_execute",
        {"stdout": "hello world", "stderr": "", "exit_code": 0}
    )
    assert "hello world" in result
    assert "EXIT CODE" in result


def test_format_tool_result_http_response():
    result = AgentScanner._format_tool_result(
        "http_request",
        {"status_code": 200, "elapsed_ms": 100, "headers": {}, "body": "OK"}
    )
    assert "HTTP 200" in result
    assert "OK" in result


def test_agent_scan_result_to_dict():
    ar = AgentScanResult(
        findings=[],
        summary="Test complete",
        risk_rating="medium",
        exploit_chains=["chain1"],
        priority_fixes=["fix1"],
        iterations_used=5,
    )
    d = ar.to_dict()
    assert d["summary"] == "Test complete"
    assert d["risk_rating"] == "medium"
    assert d["exploit_chains"] == ["chain1"]
    assert d["priority_fixes"] == ["fix1"]
    assert d["iterations_used"] == 5
    assert d["total_findings"] == 0
