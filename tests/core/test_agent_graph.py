"""Tests for multi-agent graph orchestration."""

from __future__ import annotations

import asyncio
import pytest

from vibee_hacker.core.agent_graph import (
    AgentGraph,
    AgentNode,
    AgentRole,
    AgentStatus,
    GraphResult,
    create_pentest_graph,
)


# ---------------------------------------------------------------------------
# AgentNode tests
# ---------------------------------------------------------------------------

class TestAgentNode:
    def test_agent_node_defaults(self):
        node = AgentNode(name="test", role=AgentRole.RECON)
        assert node.name == "test"
        assert node.role == AgentRole.RECON
        assert node.handler is None
        assert node.dependencies == []
        assert node.status == AgentStatus.PENDING
        assert node.result == {}
        assert node.error == ""
        assert node.timeout == 120

    def test_agent_node_is_ready(self):
        node = AgentNode(name="test", role=AgentRole.ATTACK)
        assert node.is_ready is True

        node.status = AgentStatus.RUNNING
        assert node.is_ready is False

        node.status = AgentStatus.COMPLETED
        assert node.is_ready is False

        node.status = AgentStatus.FAILED
        assert node.is_ready is False


# ---------------------------------------------------------------------------
# AgentGraph structure tests
# ---------------------------------------------------------------------------

class TestAgentGraphStructure:
    def test_add_agent(self):
        graph = AgentGraph()
        node = AgentNode(name="recon", role=AgentRole.RECON)
        graph.add_agent(node)
        assert graph.node_count == 1
        assert graph.get_node("recon") is node

    def test_add_dependency(self):
        graph = AgentGraph()
        graph.add_agent(AgentNode(name="recon", role=AgentRole.RECON))
        graph.add_agent(AgentNode(name="attack", role=AgentRole.ATTACK))
        graph.add_dependency("attack", "recon")
        assert "recon" in graph.get_node("attack").dependencies

    def test_execution_order_linear(self):
        graph = AgentGraph()
        graph.add_agent(AgentNode(name="a", role=AgentRole.RECON))
        graph.add_agent(AgentNode(name="b", role=AgentRole.ATTACK, dependencies=["a"]))
        graph.add_agent(AgentNode(name="c", role=AgentRole.REPORT, dependencies=["b"]))

        order = graph.get_execution_order()
        assert order == [["a"], ["b"], ["c"]]

    def test_execution_order_parallel(self):
        graph = AgentGraph()
        graph.add_agent(AgentNode(name="a", role=AgentRole.RECON))
        graph.add_agent(AgentNode(name="b", role=AgentRole.ATTACK))
        graph.add_agent(AgentNode(name="c", role=AgentRole.REPORT, dependencies=["a", "b"]))

        order = graph.get_execution_order()
        # a and b should be in the first layer (parallel)
        assert len(order) == 2
        assert sorted(order[0]) == ["a", "b"]
        assert order[1] == ["c"]

    def test_execution_order_cycle_detection(self):
        graph = AgentGraph()
        graph.add_agent(AgentNode(name="a", role=AgentRole.RECON, dependencies=["b"]))
        graph.add_agent(AgentNode(name="b", role=AgentRole.ATTACK, dependencies=["a"]))

        # Cycle: should return only what can be resolved (empty in this case)
        order = graph.get_execution_order()
        # Neither a nor b can run due to circular dependency
        assert order == []


# ---------------------------------------------------------------------------
# Execution tests
# ---------------------------------------------------------------------------

class TestAgentGraphExecution:
    @pytest.mark.asyncio
    async def test_execute_linear_graph(self):
        graph = AgentGraph()

        async def handler_a(ctx: dict) -> dict:
            return {"step": "a"}

        async def handler_b(ctx: dict) -> dict:
            return {"step": "b", "got_a": "a" in ctx}

        graph.add_agent(AgentNode(name="a", role=AgentRole.RECON, handler=handler_a))
        graph.add_agent(AgentNode(name="b", role=AgentRole.ATTACK, handler=handler_b, dependencies=["a"]))

        result = await graph.execute()
        assert "a" in result.completed
        assert "b" in result.completed
        assert result.failed == []

    @pytest.mark.asyncio
    async def test_execute_parallel_layer(self):
        graph = AgentGraph()
        order_log: list[str] = []

        async def handler_a(ctx: dict) -> dict:
            order_log.append("a")
            return {"step": "a"}

        async def handler_b(ctx: dict) -> dict:
            order_log.append("b")
            return {"step": "b"}

        graph.add_agent(AgentNode(name="a", role=AgentRole.RECON, handler=handler_a))
        graph.add_agent(AgentNode(name="b", role=AgentRole.ATTACK, handler=handler_b))

        result = await graph.execute()
        assert set(result.completed) == {"a", "b"}
        assert set(order_log) == {"a", "b"}

    @pytest.mark.asyncio
    async def test_execute_with_failure_skips_dependents(self):
        graph = AgentGraph()

        async def failing_handler(ctx: dict) -> dict:
            raise RuntimeError("intentional failure")

        async def dependent_handler(ctx: dict) -> dict:
            return {"step": "dependent"}

        graph.add_agent(AgentNode(name="recon", role=AgentRole.RECON, handler=failing_handler))
        graph.add_agent(AgentNode(name="attack", role=AgentRole.ATTACK, handler=dependent_handler, dependencies=["recon"]))

        result = await graph.execute()
        assert "recon" in result.failed
        assert graph.get_node("attack").status == AgentStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_execute_timeout(self):
        graph = AgentGraph()

        async def slow_handler(ctx: dict) -> dict:
            await asyncio.sleep(10)
            return {}

        graph.add_agent(AgentNode(name="slow", role=AgentRole.RECON, handler=slow_handler, timeout=1))

        result = await graph.execute()
        assert "slow" in result.failed
        node = graph.get_node("slow")
        assert "Timeout" in node.error

    @pytest.mark.asyncio
    async def test_execute_no_handler_skipped(self):
        graph = AgentGraph()
        graph.add_agent(AgentNode(name="nohandler", role=AgentRole.RECON, handler=None))

        result = await graph.execute()
        node = graph.get_node("nohandler")
        assert node.status == AgentStatus.SKIPPED
        assert "No handler" in node.error

    @pytest.mark.asyncio
    async def test_graph_result_to_dict(self):
        graph = AgentGraph()

        async def handler(ctx: dict) -> dict:
            return {"data": "value"}

        graph.add_agent(AgentNode(name="x", role=AgentRole.RECON, handler=handler))
        result = await graph.execute()

        d = result.to_dict()
        assert "completed" in d
        assert "failed" in d
        assert "total_time_ms" in d
        assert "results" in d
        assert "x" in d["completed"]

    @pytest.mark.asyncio
    async def test_create_pentest_graph(self):
        graph = create_pentest_graph()
        assert graph.node_count == 4

        result = await graph.execute(context={"target": "https://example.com"})
        assert set(result.completed) == {"recon", "attack", "verify", "report"}
        assert result.failed == []

    @pytest.mark.asyncio
    async def test_shared_context_propagation(self):
        graph = AgentGraph()
        captured: dict = {}

        async def producer(ctx: dict) -> dict:
            return {"secret": "from_producer"}

        async def consumer(ctx: dict) -> dict:
            captured.update(ctx)
            return {"consumed": True}

        graph.add_agent(AgentNode(name="producer", role=AgentRole.RECON, handler=producer))
        graph.add_agent(AgentNode(name="consumer", role=AgentRole.ATTACK, handler=consumer, dependencies=["producer"]))

        await graph.execute()
        # Consumer should have received producer's result in its context
        assert "producer" in captured
        assert captured["producer"]["secret"] == "from_producer"
