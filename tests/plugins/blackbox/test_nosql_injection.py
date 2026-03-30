# tests/plugins/blackbox/test_nosql_injection.py
import pytest
import httpx
from vibee_hacker.plugins.blackbox.nosql_injection import NoSqlInjectionPlugin
from vibee_hacker.core.models import Target, Severity


class TestNoSqlInjection:
    @pytest.fixture
    def plugin(self):
        return NoSqlInjectionPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/api/login?username=admin")

    @pytest.mark.asyncio
    async def test_nosql_detected(self, plugin, target, httpx_mock):
        # Baseline GET returns one response
        httpx_mock.add_response(
            url="https://example.com/api/login?username=admin",
            text='{"error":"invalid credentials"}',
            status_code=200,
        )
        # Operator injection POST returns DIFFERENT content (auth bypass)
        httpx_mock.add_response(
            text='{"token":"abc123","user":"admin"}',
            status_code=200,
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.CRITICAL
        assert results[0].cwe_id == "CWE-943"
        assert results[0].rule_id == "nosql_operator_injection"

    @pytest.mark.asyncio
    async def test_no_nosql(self, plugin, target, httpx_mock):
        # Baseline and all injection attempts return same content
        httpx_mock.add_response(text='{"error":"invalid credentials"}', status_code=200)
        for _ in range(3):
            httpx_mock.add_response(text='{"error":"invalid credentials"}', status_code=200)
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_no_params_skip(self, plugin, httpx_mock):
        target = Target(url="https://example.com/api/login")
        results = await plugin.run(target)
        assert results == []
