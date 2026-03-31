# tests/plugins/blackbox/test_forced_browsing.py
"""Tests for forced browsing / sensitive file exposure detection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.forced_browsing import ForcedBrowsingPlugin
from vibee_hacker.core.models import Target, Severity


class TestForcedBrowsing:
    @pytest.fixture
    def plugin(self):
        return ForcedBrowsingPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/")

    @pytest.mark.asyncio
    async def test_git_config_found(self, plugin, target, httpx_mock):
        """/.env with DB_PASSWORD signature found on first probe — reported as HIGH."""
        # /.env is the first path in SENSITIVE_FILES — make it return 200 with matching signature
        httpx_mock.add_response(
            url="https://example.com/.env",
            status_code=200,
            text="DB_PASSWORD=supersecret\nAPP_KEY=base64:abc123\n",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.HIGH
        assert results[0].rule_id == "forced_browsing_sensitive_file"
        assert results[0].cwe_id == "CWE-425"

    @pytest.mark.asyncio
    async def test_all_return_404(self, plugin, target, httpx_mock):
        """All sensitive paths returning 404 produce no results."""
        from vibee_hacker.plugins.blackbox.forced_browsing import SENSITIVE_FILES
        for _ in SENSITIVE_FILES:
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
