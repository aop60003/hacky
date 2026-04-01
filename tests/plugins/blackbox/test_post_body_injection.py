# tests/plugins/blackbox/test_post_body_injection.py
"""Tests for POST body injection in sqli, xss, cmdi plugins."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.sqli import SqliPlugin
from vibee_hacker.plugins.blackbox.xss import XssPlugin
from vibee_hacker.plugins.blackbox.cmdi import CmdiPlugin
from vibee_hacker.core.models import Target, Severity, InterPhaseContext


# ------------------------------------------------------------------ #
# SQLi POST body injection
# ------------------------------------------------------------------ #
class TestSqliPostBody:
    @pytest.fixture
    def plugin(self):
        return SqliPlugin()

    @pytest.fixture
    def target(self):
        # No GET params — POST only
        return Target(url="https://example.com/login")

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_responses_were_requested=False)
    async def test_post_sqli_detected(self, plugin, target, httpx_mock):
        """SQL error in POST body response is reported."""
        # Baseline GET returns normal
        httpx_mock.add_response(text="<html>Normal page</html>")
        # First POST returns SQL error
        httpx_mock.add_response(
            text="You have an error in your SQL syntax near",
        )
        # Extra responses to consume remaining requests
        for _ in range(50):
            httpx_mock.add_response(text="<html>Normal page</html>")

        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.CRITICAL

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_responses_were_requested=False)
    async def test_post_no_sqli_empty(self, plugin, target, httpx_mock):
        """No SQL error in POST responses returns empty."""
        for _ in range(100):
            httpx_mock.add_response(text="<html>Normal page</html>")
        results = await plugin.run(target)
        assert results == []


# ------------------------------------------------------------------ #
# XSS POST body injection
# ------------------------------------------------------------------ #
class TestXssPostBody:
    @pytest.fixture
    def plugin(self):
        return XssPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/search")

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_responses_were_requested=False)
    async def test_post_xss_detected(self, plugin, target, httpx_mock):
        """XSS payload reflected in POST response is reported."""
        # First POST has reflected XSS
        httpx_mock.add_response(
            headers={"content-type": "text/html"},
            text="<html><script>alert('vbh')</script></html>",
        )
        for _ in range(50):
            httpx_mock.add_response(
                headers={"content-type": "text/html"},
                text="<html>Normal</html>",
            )

        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.HIGH

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_responses_were_requested=False)
    async def test_post_no_xss_empty(self, plugin, target, httpx_mock):
        """No XSS reflection in POST responses returns empty."""
        for _ in range(100):
            httpx_mock.add_response(
                headers={"content-type": "text/html"},
                text="<html>Normal page</html>",
            )
        results = await plugin.run(target)
        assert results == []


# ------------------------------------------------------------------ #
# CMDi POST body injection
# ------------------------------------------------------------------ #
class TestCmdiPostBody:
    @pytest.fixture
    def plugin(self):
        return CmdiPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/ping")

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_responses_were_requested=False)
    async def test_post_cmdi_detected(self, plugin, target, httpx_mock):
        """Command marker in POST response is reported."""
        # Baseline GET returns normal
        httpx_mock.add_response(text="<html>Normal</html>")
        # First POST returns marker
        httpx_mock.add_response(text="VIBEE_CMD_MARKER output")
        for _ in range(50):
            httpx_mock.add_response(text="<html>Normal</html>")

        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.CRITICAL

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_responses_were_requested=False)
    async def test_post_no_cmdi_empty(self, plugin, target, httpx_mock):
        """No marker in POST responses returns empty."""
        for _ in range(100):
            httpx_mock.add_response(text="<html>Normal</html>")
        results = await plugin.run(target)
        assert results == []
