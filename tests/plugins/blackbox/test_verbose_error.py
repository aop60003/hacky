# tests/plugins/blackbox/test_verbose_error.py
"""Tests for verbose error disclosure plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.verbose_error import VerboseErrorPlugin
from vibee_hacker.core.models import Target, Severity


class TestVerboseError:
    @pytest.fixture
    def plugin(self):
        return VerboseErrorPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/")

    @pytest.mark.asyncio
    async def test_traceback_in_error_response(self, plugin, target, httpx_mock):
        """Traceback in error response is reported as MEDIUM."""
        from vibee_hacker.plugins.blackbox.verbose_error import ERROR_PATHS
        # First error path returns a traceback
        httpx_mock.add_response(
            url=f"https://example.com{ERROR_PATHS[0]}",
            status_code=500,
            text="Traceback (most recent call last):\n  File app.py, line 42, in handler\nValueError: invalid input",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.MEDIUM
        assert results[0].rule_id == "verbose_error_disclosure"
        assert results[0].cwe_id == "CWE-209"

    @pytest.mark.asyncio
    async def test_clean_error_page(self, plugin, target, httpx_mock):
        """Clean generic error pages produce no results."""
        from vibee_hacker.plugins.blackbox.verbose_error import ERROR_PATHS
        for _ in range(len(ERROR_PATHS)):
            httpx_mock.add_response(
                status_code=404,
                text="<html><body>Page Not Found</body></html>",
            )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport error returns empty results gracefully."""
        from vibee_hacker.plugins.blackbox.verbose_error import ERROR_PATHS
        for _ in range(len(ERROR_PATHS)):
            httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []
