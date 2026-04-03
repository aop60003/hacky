"""Multi-agent graph orchestration: specialized agents collaborate via DAG."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Awaitable

logger = logging.getLogger(__name__)


class AgentRole(str, Enum):
    RECON = "recon"
    ATTACK = "attack"
    VERIFY = "verify"
    REPORT = "report"
    CUSTOM = "custom"


class AgentStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class AgentNode:
    """A single agent in the graph."""
    name: str
    role: AgentRole
    handler: Callable[..., Awaitable[dict]] | None = None
    dependencies: list[str] = field(default_factory=list)  # names of upstream agents
    status: AgentStatus = AgentStatus.PENDING
    result: dict = field(default_factory=dict)
    error: str = ""
    timeout: int = 120

    @property
    def is_ready(self) -> bool:
        """Can run if all dependencies are completed."""
        return self.status == AgentStatus.PENDING


@dataclass
class GraphResult:
    """Result of a full graph execution."""
    nodes: dict[str, AgentNode] = field(default_factory=dict)
    total_time_ms: float = 0.0

    @property
    def completed(self) -> list[str]:
        return [n for n, node in self.nodes.items() if node.status == AgentStatus.COMPLETED]

    @property
    def failed(self) -> list[str]:
        return [n for n, node in self.nodes.items() if node.status == AgentStatus.FAILED]

    @property
    def all_results(self) -> dict[str, dict]:
        return {n: node.result for n, node in self.nodes.items() if node.result}

    def to_dict(self) -> dict:
        return {
            "completed": self.completed,
            "failed": self.failed,
            "total_time_ms": self.total_time_ms,
            "results": {n: node.result for n, node in self.nodes.items()},
        }


class AgentGraph:
    """DAG-based multi-agent orchestrator."""

    def __init__(self, max_concurrency: int = 5):
        self._nodes: dict[str, AgentNode] = {}
        self._semaphore = asyncio.Semaphore(max_concurrency)

    def add_agent(self, node: AgentNode):
        """Add an agent node to the graph."""
        self._nodes[node.name] = node

    def add_dependency(self, agent_name: str, depends_on: str):
        """Add a dependency between agents."""
        if agent_name in self._nodes:
            self._nodes[agent_name].dependencies.append(depends_on)

    def get_execution_order(self) -> list[list[str]]:
        """Get topological execution order (layers for parallel execution)."""
        remaining = set(self._nodes.keys())
        completed: set[str] = set()
        layers: list[list[str]] = []

        while remaining:
            # Find nodes whose dependencies are all completed
            ready = []
            for name in remaining:
                deps = set(self._nodes[name].dependencies)
                if deps.issubset(completed):
                    ready.append(name)

            if not ready:
                # Cycle detected or unresolvable deps
                break

            layers.append(sorted(ready))
            completed.update(ready)
            remaining -= set(ready)

        return layers

    async def execute(self, context: dict | None = None) -> GraphResult:
        """Execute all agents in topological order with parallelism."""
        import time
        start = time.monotonic()

        shared_context = dict(context or {})
        layers = self.get_execution_order()

        for layer in layers:
            # Run all agents in this layer concurrently
            tasks = [self._run_agent(self._nodes[name], shared_context) for name in layer]
            await asyncio.gather(*tasks)

            # Merge results into shared context
            for name in layer:
                node = self._nodes[name]
                if node.status == AgentStatus.COMPLETED and node.result:
                    shared_context[node.name] = node.result

        elapsed = (time.monotonic() - start) * 1000
        return GraphResult(nodes=dict(self._nodes), total_time_ms=elapsed)

    async def _run_agent(self, node: AgentNode, context: dict):
        """Run a single agent node."""
        # Check if all dependencies succeeded
        for dep in node.dependencies:
            dep_node = self._nodes.get(dep)
            if dep_node and dep_node.status != AgentStatus.COMPLETED:
                node.status = AgentStatus.SKIPPED
                node.error = f"Dependency {dep} did not complete"
                return

        if not node.handler:
            node.status = AgentStatus.SKIPPED
            node.error = "No handler defined"
            return

        async with self._semaphore:
            node.status = AgentStatus.RUNNING
            try:
                result = await asyncio.wait_for(
                    node.handler(context),
                    timeout=node.timeout,
                )
                node.result = result or {}
                node.status = AgentStatus.COMPLETED
            except asyncio.TimeoutError:
                node.status = AgentStatus.FAILED
                node.error = f"Timeout after {node.timeout}s"
            except Exception as e:
                node.status = AgentStatus.FAILED
                node.error = str(e)

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    def get_node(self, name: str) -> AgentNode | None:
        return self._nodes.get(name)


# Pre-built graph templates
def create_pentest_graph() -> AgentGraph:
    """Create a standard pentest workflow graph."""
    graph = AgentGraph()

    async def recon_handler(ctx: dict) -> dict:
        return {"target": ctx.get("target", ""), "phase": "recon_complete"}

    async def attack_handler(ctx: dict) -> dict:
        recon_data = ctx.get("recon", {})
        return {"findings": [], "phase": "attack_complete", "recon_used": bool(recon_data)}

    async def verify_handler(ctx: dict) -> dict:
        return {"verified": [], "phase": "verify_complete"}

    async def report_handler(ctx: dict) -> dict:
        return {"report": "generated", "phase": "report_complete"}

    graph.add_agent(AgentNode(name="recon", role=AgentRole.RECON, handler=recon_handler))
    graph.add_agent(AgentNode(name="attack", role=AgentRole.ATTACK, handler=attack_handler, dependencies=["recon"]))
    graph.add_agent(AgentNode(name="verify", role=AgentRole.VERIFY, handler=verify_handler, dependencies=["attack"]))
    graph.add_agent(AgentNode(name="report", role=AgentRole.REPORT, handler=report_handler, dependencies=["verify"]))

    return graph
