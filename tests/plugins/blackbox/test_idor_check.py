# tests/plugins/blackbox/test_idor_check.py
import pytest
import httpx
from vibee_hacker.plugins.blackbox.idor_check import IdorCheckPlugin
from vibee_hacker.core.models import Target, Severity


class TestIdorCheck:
    @pytest.fixture
    def plugin(self):
        return IdorCheckPlugin()

    @pytest.mark.asyncio
    async def test_idor_detected(self, plugin, httpx_mock):
        # Original resource at /api/users/123
        target = Target(url="https://example.com/api/users/123")
        httpx_mock.add_response(
            url="https://example.com/api/users/123",
            text='{"id":123,"name":"Alice","email":"alice@example.com"}',
            status_code=200,
        )
        # Adjacent ID 124 also returns a valid user (different data)
        httpx_mock.add_response(
            text='{"id":124,"name":"Bob","email":"bob@example.com"}',
            status_code=200,
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.HIGH
        assert results[0].cwe_id == "CWE-639"
        assert results[0].rule_id == "idor_id_enumeration"

    @pytest.mark.asyncio
    async def test_no_idor(self, plugin, httpx_mock):
        target = Target(url="https://example.com/api/users/123")
        # Original resource returns 200
        httpx_mock.add_response(
            url="https://example.com/api/users/123",
            text='{"id":123,"name":"Alice"}',
            status_code=200,
        )
        # Adjacent ID returns 403 (access denied)
        httpx_mock.add_response(
            text="Forbidden",
            status_code=403,
        )
        # Second adjacent ID also returns 404
        httpx_mock.add_response(
            text="Not Found",
            status_code=404,
        )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_no_numeric_id(self, plugin, httpx_mock):
        target = Target(url="https://example.com/api/users/alice")
        results = await plugin.run(target)
        assert results == []
