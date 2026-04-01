# tests/plugins/blackbox/test_cve_lookup.py
"""Tests for CveLookupPlugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.cve_lookup import CveLookupPlugin
from vibee_hacker.core.models import Target, Severity, InterPhaseContext


class TestCveLookup:
    @pytest.fixture
    def plugin(self):
        return CveLookupPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/")

    # ------------------------------------------------------------------ #
    # Test 1: Apache/2.4.49 detected → CVE reported
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_apache_2449_cve_reported(self, plugin, target, httpx_mock):
        """Apache/2.4.49 triggers CVE-2021-41773 (path traversal)."""
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=200,
            headers={"server": "Apache/2.4.49", "content-type": "text/html"},
            text="<html>Apache server</html>",
        )
        ctx = InterPhaseContext(tech_stack=["Apache/2.4.49"])
        results = await plugin.run(target, ctx)
        assert len(results) >= 1
        r = results[0]
        assert "CVE-2021-41773" in r.title or "CVE-2021-41773" in r.description
        assert r.base_severity == Severity.CRITICAL
        assert r.rule_id == "cve_known"

    # ------------------------------------------------------------------ #
    # Test 2: No version info → empty
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_no_version_info_empty(self, plugin, target, httpx_mock):
        """When no version info is present, no CVE is reported."""
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=200,
            headers={"content-type": "text/html"},
            text="<html>Generic page</html>",
        )
        ctx = InterPhaseContext()
        results = await plugin.run(target, ctx)
        assert results == []

    # ------------------------------------------------------------------ #
    # Test 3: Up-to-date / unknown version → empty
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_unknown_version_empty(self, plugin, target, httpx_mock):
        """An Apache version not in the CVE database returns empty."""
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=200,
            headers={"server": "Apache/2.4.57", "content-type": "text/html"},
            text="<html>Apache 2.4.57</html>",
        )
        ctx = InterPhaseContext(tech_stack=["Apache/2.4.57"])
        results = await plugin.run(target, ctx)
        assert results == []
