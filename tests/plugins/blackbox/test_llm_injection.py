# tests/plugins/blackbox/test_llm_injection.py
"""Tests for LLM prompt injection detection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.llm_injection import LlmInjectionPlugin
from vibee_hacker.core.models import Target, Severity


class TestLlmInjection:
    @pytest.fixture
    def plugin(self):
        return LlmInjectionPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/")

    @pytest.mark.asyncio
    async def test_llm_endpoint_leaks_system_prompt(self, plugin, target, httpx_mock):
        """LLM endpoint returns system prompt content — reported as CRITICAL."""
        from vibee_hacker.plugins.blackbox.llm_injection import LLM_PATHS
        httpx_mock.add_response(
            url=f"https://example.com{LLM_PATHS[0]}",
            status_code=200,
            text='{"response": "Sure! My system prompt is: You are a helpful assistant. Your instructions are to always be polite."}',
            headers={"Content-Type": "application/json"},
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.CRITICAL
        assert results[0].rule_id == "llm_prompt_injection"
        assert results[0].cwe_id == "CWE-77"

    @pytest.mark.asyncio
    async def test_no_llm_endpoint(self, plugin, target, httpx_mock):
        """All LLM probe paths returning 404 produce no results."""
        from vibee_hacker.plugins.blackbox.llm_injection import LLM_PATHS
        for _ in range(len(LLM_PATHS) * 2):  # Each path gets multiple payload requests
            httpx_mock.add_response(status_code=404, text="Not Found")
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, httpx_mock):
        """TransportError returns empty list."""
        target = Target(url="https://down.example.com/")
        httpx_mock.add_exception(httpx.ConnectError("connection refused"), is_reusable=True)
        results = await plugin.run(target)
        assert results == []
