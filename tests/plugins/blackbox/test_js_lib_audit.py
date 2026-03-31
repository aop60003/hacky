# tests/plugins/blackbox/test_js_lib_audit.py
"""Tests for JavaScript library audit plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.js_lib_audit import JsLibAuditPlugin
from vibee_hacker.core.models import Target, Severity


class TestJsLibAudit:
    @pytest.fixture
    def plugin(self):
        return JsLibAuditPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/")

    @pytest.mark.asyncio
    async def test_old_jquery_detected(self, plugin, target, httpx_mock):
        """Old jQuery version in script tag is reported as MEDIUM."""
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=200,
            text=(
                '<html><head>'
                '<script src="/js/jquery-1.12.4.min.js"></script>'
                '</head><body>Hello</body></html>'
            ),
            headers={"content-type": "text/html"},
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.MEDIUM
        assert results[0].rule_id == "js_lib_vulnerable"
        assert results[0].cwe_id == "CWE-1104"

    @pytest.mark.asyncio
    async def test_no_vulnerable_libs(self, plugin, target, httpx_mock):
        """Modern library versions produce no results."""
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=200,
            text=(
                '<html><head>'
                '<script src="/js/jquery-3.7.1.min.js"></script>'
                '</head><body>Hello</body></html>'
            ),
            headers={"content-type": "text/html"},
        )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_no_scripts_no_finding(self, plugin, target, httpx_mock):
        """Page with no script tags produces no results."""
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=200,
            text="<html><head></head><body>Hello</body></html>",
            headers={"content-type": "text/html"},
        )
        results = await plugin.run(target)
        assert len(results) == 0
