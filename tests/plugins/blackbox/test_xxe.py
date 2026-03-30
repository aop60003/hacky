# tests/plugins/blackbox/test_xxe.py
import pytest
import httpx
from vibee_hacker.plugins.blackbox.xxe import XxePlugin
from vibee_hacker.core.models import Target, Severity


class TestXxe:
    @pytest.fixture
    def plugin(self):
        return XxePlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/api/data")

    @pytest.mark.asyncio
    async def test_xxe_detected(self, plugin, target, httpx_mock):
        # Server responds with /etc/passwd content
        httpx_mock.add_response(
            url="https://example.com/api/data",
            text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:",
            status_code=200,
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.CRITICAL
        assert results[0].cwe_id == "CWE-611"
        assert results[0].rule_id == "xxe_entity_injection"

    @pytest.mark.asyncio
    async def test_no_xxe(self, plugin, target, httpx_mock):
        # Normal error response — no file content
        httpx_mock.add_response(
            url="https://example.com/api/data",
            text="<error>Invalid XML</error>",
            status_code=400,
        )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_transport_error(self, plugin, target, httpx_mock):
        # Connection refused — returns empty
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []
