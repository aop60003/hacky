# tests/plugins/blackbox/test_xss.py
import pytest
import httpx
from vibee_hacker.plugins.blackbox.xss import XssPlugin
from vibee_hacker.core.models import Target, Severity


class TestXss:
    @pytest.fixture
    def plugin(self):
        return XssPlugin()

    @pytest.mark.asyncio
    async def test_reflected_xss_detected(self, plugin, httpx_mock):
        target = Target(url="https://example.com/search?q=test")
        httpx_mock.add_response(
            url="https://example.com/search?q=%3Cscript%3Ealert%28%27vbh%27%29%3C%2Fscript%3E",
            headers={"content-type": "text/html; charset=utf-8"},
            text="<html>Results for <script>alert('vbh')</script></html>",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_no_xss(self, plugin, httpx_mock):
        target = Target(url="https://example.com/search?q=test")
        # Return escaped content for all payload requests (no XSS)
        httpx_mock.add_response(text="<html>Results for &lt;script&gt;alert('vbh')&lt;/script&gt;</html>")
        httpx_mock.add_response(text="<html>Results for &lt;script&gt;alert('vbh')&lt;/script&gt;</html>")
        httpx_mock.add_response(text="<html>Results for &lt;script&gt;alert('vbh')&lt;/script&gt;</html>")
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_no_params_skip(self, plugin, httpx_mock):
        target = Target(url="https://example.com/")
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, httpx_mock):
        target = Target(url="https://down.example.com/page?q=test")
        # XssPlugin iterates all 3 payloads, catching TransportError on each
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []
