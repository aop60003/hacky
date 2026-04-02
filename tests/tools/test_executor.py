"""Tests for tool executor dispatch."""
from __future__ import annotations

import pytest
from vibee_hacker.tools.registry import register_tool, clear_registry
from vibee_hacker.tools.executor import execute_tool, execute_tool_batch


@pytest.fixture(autouse=True)
def isolated_registry():
    """Each test runs with a clean registry snapshot restored after."""
    from vibee_hacker.tools import registry as reg
    tools_backup = list(reg._tools)
    by_name_backup = dict(reg._tools_by_name)
    schemas_backup = dict(reg._tool_schemas)
    yield
    reg._tools[:] = tools_backup
    reg._tools_by_name.clear()
    reg._tools_by_name.update(by_name_backup)
    reg._tool_schemas.clear()
    reg._tool_schemas.update(schemas_backup)


@pytest.mark.asyncio
async def test_execute_tool_unknown_returns_error():
    result = await execute_tool("tool_that_does_not_exist_xyz")
    assert "error" in result
    assert "not found" in result["error"].lower()


@pytest.mark.asyncio
async def test_execute_tool_sync_function():
    @register_tool(description="Sync tool for testing")
    def executor_sync_tool(value: int) -> dict:
        return {"result": value * 2}

    result = await execute_tool("executor_sync_tool", value=7)
    assert result == {"result": 14}


@pytest.mark.asyncio
async def test_execute_tool_async_function():
    import asyncio

    @register_tool(description="Async tool for testing")
    async def executor_async_tool(text: str) -> dict:
        await asyncio.sleep(0)
        return {"echo": text}

    result = await execute_tool("executor_async_tool", text="hello")
    assert result == {"echo": "hello"}


@pytest.mark.asyncio
async def test_execute_tool_missing_required_arg():
    @register_tool(description="Required arg tool")
    def executor_required_arg_tool(must_have: str) -> dict:
        return {"v": must_have}

    result = await execute_tool("executor_required_arg_tool")
    assert "error" in result
    assert "must_have" in result["error"] or "Missing" in result["error"]


@pytest.mark.asyncio
async def test_execute_tool_batch():
    @register_tool(description="Batch tool")
    def executor_batch_tool(n: int) -> dict:
        return {"n": n}

    invocations = [
        {"tool_name": "executor_batch_tool", "kwargs": {"n": 1}},
        {"tool_name": "executor_batch_tool", "kwargs": {"n": 2}},
        {"tool_name": "nonexistent_batch_tool", "kwargs": {}},
    ]
    results = await execute_tool_batch(invocations)
    assert len(results) == 3
    assert results[0] == {"n": 1}
    assert results[1] == {"n": 2}
    assert "error" in results[2]
