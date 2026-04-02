"""Tool executor with local/sandbox dispatch.

Routes tool execution to either local function calls or sandboxed
environments based on tool metadata and runtime configuration.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from vibee_hacker.tools.registry import get_tool_by_name, get_tool_schema

logger = logging.getLogger(__name__)


async def execute_tool(
    tool_name: str,
    sandbox: Optional[Any] = None,
    **kwargs: Any,
) -> Any:
    """Execute a tool, dispatching to sandbox or local based on config.

    Args:
        tool_name: Name of the registered tool.
        sandbox: Optional SandboxInfo for sandboxed execution.
        **kwargs: Arguments to pass to the tool.

    Returns:
        Tool execution result.
    """
    fn = get_tool_by_name(tool_name)
    if fn is None:
        return {"error": f"Tool not found: {tool_name}"}

    # Validate arguments
    schema = get_tool_schema(tool_name)
    if schema:
        missing = [p for p in schema.get("required", []) if p not in kwargs]
        if missing:
            return {"error": f"Missing required arguments: {missing}"}

    # Execute
    try:
        import asyncio
        if asyncio.iscoroutinefunction(fn):
            result = await fn(**kwargs)
        else:
            result = fn(**kwargs)
        return result
    except Exception as e:
        logger.error("Tool %s execution failed: %s", tool_name, e)
        return {"error": f"Tool execution failed: {e}"}


async def execute_tool_batch(
    invocations: List[Dict[str, Any]],
) -> List[Any]:
    """Execute multiple tool invocations and return results.

    Args:
        invocations: List of {"tool_name": str, "kwargs": dict}.

    Returns:
        List of results in the same order.
    """
    results = []
    for inv in invocations:
        tool_name = inv.get("tool_name", "")
        kwargs = inv.get("kwargs", {})
        result = await execute_tool(tool_name, **kwargs)
        results.append(result)
    return results
