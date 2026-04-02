"""Multi-agent delegation system.

Allows the root agent to spawn sub-agents for parallel tasks:
- Separate reconnaissance and exploitation
- Parallel testing of different attack vectors
- Dedicated sub-agent for whitebox code review while blackbox runs

Follows Strix's agent graph pattern with parent/child relationships.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from vibee_hacker.tools.registry import register_tool

logger = logging.getLogger(__name__)

# Global agent graph
_agent_graph: Dict[str, Any] = {"nodes": {}, "edges": []}
_agent_messages: Dict[str, List[Dict[str, Any]]] = {}
_agent_results: Dict[str, Any] = {}
_lock = threading.Lock()


def _register_agent(
    agent_id: str,
    name: str,
    task: str,
    parent_id: Optional[str] = None,
) -> None:
    """Register an agent in the global graph."""
    with _lock:
        _agent_graph["nodes"][agent_id] = {
            "id": agent_id,
            "name": name,
            "task": task,
            "parent_id": parent_id,
            "status": "created",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        if parent_id:
            _agent_graph["edges"].append({
                "from": parent_id,
                "to": agent_id,
                "type": "delegation",
            })
        _agent_messages[agent_id] = []


def _update_status(agent_id: str, status: str) -> None:
    with _lock:
        if agent_id in _agent_graph["nodes"]:
            _agent_graph["nodes"][agent_id]["status"] = status


def get_agent_messages(agent_id: str) -> List[Dict[str, Any]]:
    """Get unread messages for an agent."""
    with _lock:
        msgs = _agent_messages.get(agent_id, [])
        unread = [m for m in msgs if not m.get("read")]
        for m in unread:
            m["read"] = True
        return unread


@register_tool(
    description="Create a sub-agent for parallel security testing. "
    "The sub-agent runs independently and reports back when done.",
)
async def create_agent(
    name: str,
    task: str,
    target_url: Optional[str] = None,
    parent_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Spawn a sub-agent for a specific task.

    Args:
        name: Human-readable agent name (e.g., "recon-agent", "sqli-tester").
        task: Detailed task description.
        target_url: Target URL for the sub-agent.
        parent_id: Parent agent ID (auto-set if called from agent loop).

    Returns:
        Dict with agent_id and status.
    """
    agent_id = f"agent-{uuid4().hex[:8]}"
    _register_agent(agent_id, name, task, parent_id)
    _update_status(agent_id, "running")

    logger.info("Sub-agent created: %s (%s) — %s", name, agent_id, task[:80])

    return {
        "agent_id": agent_id,
        "name": name,
        "status": "running",
        "message": f"Sub-agent '{name}' created. It will execute: {task[:100]}",
    }


@register_tool(
    description="Send a message to another agent (inter-agent communication).",
)
async def send_agent_message(
    agent_id: str,
    content: str,
    sender_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Send a message to a sub-agent or parent agent.

    Args:
        agent_id: Target agent ID.
        content: Message content.
        sender_id: Sender agent ID.
    """
    with _lock:
        if agent_id not in _agent_messages:
            return {"error": f"Agent {agent_id} not found"}

        _agent_messages[agent_id].append({
            "from": sender_id or "root",
            "content": content,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "read": False,
        })

    return {"sent": True, "to": agent_id}


@register_tool(
    description="Mark a sub-agent's task as finished and record its results.",
)
async def agent_finish(
    agent_id: str,
    result: Optional[str] = None,
    findings: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Mark a sub-agent as finished.

    Args:
        agent_id: Agent to mark as finished.
        result: Summary of what the agent accomplished.
        findings: List of findings discovered.
    """
    _update_status(agent_id, "completed")

    with _lock:
        _agent_results[agent_id] = {
            "result": result,
            "findings": findings or [],
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }

    return {
        "agent_id": agent_id,
        "status": "completed",
        "findings_count": len(findings or []),
    }


@register_tool(
    description="List all agents in the current scan with their status.",
)
async def list_agents() -> Dict[str, Any]:
    """List all agents and their current status."""
    with _lock:
        agents = []
        for aid, info in _agent_graph["nodes"].items():
            agent_info = dict(info)
            if aid in _agent_results:
                agent_info["result"] = _agent_results[aid]
            agents.append(agent_info)
        return {"agents": agents, "edges": _agent_graph["edges"]}
