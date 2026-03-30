# tests/plugins/blackbox/test_robots_sitemap.py
"""Tests for robots.txt / sitemap.xml parser plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.robots_sitemap_parser import RobotsSitemapPlugin
from vibee_hacker.core.models import Target, Severity


class TestRobotsSitemap:
    @pytest.fixture
    def plugin(self):
        return RobotsSitemapPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/")

    @pytest.mark.asyncio
    async def test_robots_with_disallow_paths(self, plugin, target, httpx_mock):
        """Disallow paths in robots.txt are reported as sensitive paths."""
        httpx_mock.add_response(
            url="https://example.com/robots.txt",
            status_code=200,
            text=(
                "User-agent: *\n"
                "Disallow: /admin/\n"
                "Disallow: /secret/\n"
                "Disallow: /backup/\n"
            ),
        )
        httpx_mock.add_response(
            url="https://example.com/sitemap.xml",
            status_code=404,
            text="Not Found",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.INFO
        assert results[0].rule_id == "robots_sensitive_path"
        evidence_combined = " ".join(r.evidence for r in results)
        assert "/admin/" in evidence_combined or "/secret/" in evidence_combined

    @pytest.mark.asyncio
    async def test_no_robots_txt(self, plugin, target, httpx_mock):
        """404 on robots.txt returns no results."""
        httpx_mock.add_response(
            url="https://example.com/robots.txt",
            status_code=404,
            text="Not Found",
        )
        httpx_mock.add_response(
            url="https://example.com/sitemap.xml",
            status_code=404,
            text="Not Found",
        )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport error returns empty results gracefully."""
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []
