"""Thinking tool: explicit reasoning step for the agent.

Forces the agent to articulate its reasoning before acting.
No external side effects — purely a structured thinking step.
"""

from __future__ import annotations

from typing import Any, Dict

from vibee_hacker.tools.registry import register_tool


@register_tool(
    description="Record your reasoning process. Use this to think through "
    "complex decisions before taking action. No side effects.",
)
def think(thought: str) -> Dict[str, Any]:
    """Record a reasoning step. Returns confirmation."""
    if not thought or not thought.strip():
        return {"error": "Thought cannot be empty"}
    return {"recorded": True, "length": len(thought.strip())}
