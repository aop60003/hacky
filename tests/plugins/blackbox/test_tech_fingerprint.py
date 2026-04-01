# tests/plugins/blackbox/test_tech_fingerprint.py
"""Tests for TechFingerprintPlugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.tech_fingerprint import TechFingerprintPlugin
from vibee_hacker.core.models import Target, Severity, InterPhaseContext


class TestTechFingerprint:
    @pytest.fixture
    def plugin(self):
        return TechFingerprintPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/")

    # ------------------------------------------------------------------ #
    # Test 1: Nginx + PHP detected from headers
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_nginx_php_from_headers(self, plugin, target, httpx_mock):
        """Nginx and PHP are identified from response headers."""
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=200,
            headers={
                "server": "nginx/1.18.0",
                "x-powered-by": "PHP/8.0.1",
                "content-type": "text/html",
            },
            text="<html><body>Hello</body></html>",
        )
        ctx = InterPhaseContext()
        results = await plugin.run(target, ctx)
        assert len(results) >= 1
        # tech_stack should be populated
        assert any("nginx" in t.lower() for t in ctx.tech_stack)
        assert any("php" in t.lower() for t in ctx.tech_stack)
        assert all(r.rule_id == "tech_detected" for r in results)
        assert all(r.base_severity == Severity.INFO for r in results)

    # ------------------------------------------------------------------ #
    # Test 2: WordPress detected from HTML body
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_wordpress_from_html(self, plugin, target, httpx_mock):
        """WordPress is identified from wp-content in page body."""
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=200,
            headers={"content-type": "text/html"},
            text='<html><head><link rel="stylesheet" href="/wp-content/themes/default.css"></head></html>',
        )
        ctx = InterPhaseContext()
        results = await plugin.run(target, ctx)
        assert len(results) >= 1
        assert any("wordpress" in t.lower() for t in ctx.tech_stack)

    # ------------------------------------------------------------------ #
    # Test 3: No tech markers → empty
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_no_markers_empty(self, plugin, target, httpx_mock):
        """A generic response with no tech fingerprints returns empty."""
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=200,
            headers={"content-type": "text/html"},
            text="<html><body>Hello World</body></html>",
        )
        ctx = InterPhaseContext()
        results = await plugin.run(target, ctx)
        assert results == []

    # ------------------------------------------------------------------ #
    # Test 4: Transport error → empty
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport errors during fingerprinting are handled gracefully."""
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        ctx = InterPhaseContext()
        results = await plugin.run(target, ctx)
        assert results == []
