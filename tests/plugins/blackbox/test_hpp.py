# tests/plugins/blackbox/test_hpp.py
"""Tests for HTTP Parameter Pollution (HPP) detection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.hpp import HppPlugin, MARKER_A, MARKER_B
from vibee_hacker.core.models import Target, Severity


class TestHpp:
    @pytest.fixture
    def plugin(self):
        return HppPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/search?q=test")

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_second_marker_reflected_is_vulnerable(self, plugin, target, httpx_mock):
        """Server reflects MARKER_B (second duplicate param value) — reported as MEDIUM."""
        httpx_mock.add_response(
            status_code=200,
            text=f"<html>Results for: {MARKER_B}</html>",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].rule_id == "hpp_duplicate_param"
        assert results[0].cwe_id == "CWE-235"
        assert results[0].base_severity == Severity.MEDIUM

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_both_markers_reflected_is_vulnerable(self, plugin, target, httpx_mock):
        """Server reflects both marker values — reported as MEDIUM."""
        httpx_mock.add_response(
            status_code=200,
            text=f"<html>Results: {MARKER_A} and {MARKER_B}</html>",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].rule_id == "hpp_duplicate_param"

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_no_marker_reflected_not_vulnerable(self, plugin, target, httpx_mock):
        """Server does not reflect markers — no results."""
        httpx_mock.add_response(
            status_code=200,
            text="<html>Normal response with no special values</html>",
        )
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_url_returns_empty(self, plugin):
        """Target with no URL returns empty."""
        results = await plugin.run(Target(url=None, path="/some/path", mode="whitebox"))
        assert results == []

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, httpx_mock):
        """TransportError returns empty list."""
        target = Target(url="https://down.example.com/search?q=test")
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []
