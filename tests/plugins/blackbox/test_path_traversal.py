# tests/plugins/blackbox/test_path_traversal.py
import pytest
import httpx
from vibee_hacker.plugins.blackbox.path_traversal import PathTraversalPlugin
from vibee_hacker.core.models import Target, Severity


class TestPathTraversal:
    @pytest.fixture
    def plugin(self):
        return PathTraversalPlugin()

    @pytest.mark.asyncio
    async def test_lfi_detected(self, plugin, httpx_mock):
        target = Target(url="https://example.com/read?file=report.pdf")
        httpx_mock.add_response(
            url="https://example.com/read?file=report.pdf",
            text="PDF content",
        )
        httpx_mock.add_response(
            url="https://example.com/read?file=..%2F..%2F..%2Fetc%2Fpasswd",
            text="root:x:0:0:root:/root:/bin/bash",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_no_traversal(self, plugin, httpx_mock):
        target = Target(url="https://example.com/read?file=report.pdf")
        # Return safe response for baseline + all payload requests (no file signatures)
        httpx_mock.add_response(text="File not found")
        httpx_mock.add_response(text="File not found")
        httpx_mock.add_response(text="File not found")
        httpx_mock.add_response(text="File not found")
        httpx_mock.add_response(text="File not found")
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, httpx_mock):
        target = Target(url="https://down.example.com/page?q=test")
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []
