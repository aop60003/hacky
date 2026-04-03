"""Tests for DOM-based XSS and Prototype Pollution detection."""

from __future__ import annotations

import pytest
import httpx

from vibee_hacker.plugins.blackbox.dom_xss import DomXssPlugin
from vibee_hacker.core.models import Target, Severity


@pytest.fixture
def plugin():
    return DomXssPlugin()


class TestDomXssApplicability:
    def test_is_applicable(self, plugin):
        target = Target(url="https://example.com")
        assert plugin.is_applicable(target) is True

    def test_no_url_returns_empty(self, plugin):
        """Plugin with no URL produces no results without HTTP calls."""
        target = Target(url=None, path="/some/path", mode="whitebox")
        # is_applicable is False, but run() must also guard correctly
        assert plugin.is_applicable(target) is False


class TestDomXssDetection:
    @pytest.mark.asyncio
    async def test_dom_xss_source_sink(self, plugin, httpx_mock):
        """Page with location.hash (source) + innerHTML= (sink) → HIGH finding."""
        page = """
        <html><body>
        <script>
            var hash = location.hash;
            document.getElementById('out').innerHTML = hash;
        </script>
        </body></html>
        """
        httpx_mock.add_response(status_code=200, text=page)
        target = Target(url="https://example.com")
        results = await plugin.run(target)

        assert len(results) >= 1
        finding = next(r for r in results if r.rule_id == "dom_xss_source_sink")
        assert finding.base_severity == Severity.HIGH
        assert finding.cwe_id == "CWE-79"

    @pytest.mark.asyncio
    async def test_dom_xss_sinks_only(self, plugin, httpx_mock):
        """Page with innerHTML but no DOM source → MEDIUM finding for dangerous sinks."""
        page = """
        <html><body>
        <script>
            var userInput = document.getElementById('field').value;
            document.getElementById('out').innerHTML = userInput;
        </script>
        </body></html>
        """
        httpx_mock.add_response(status_code=200, text=page)
        target = Target(url="https://example.com")
        results = await plugin.run(target)

        assert len(results) >= 1
        finding = next(r for r in results if r.rule_id == "dom_xss_dangerous_sinks")
        assert finding.base_severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_prototype_pollution(self, plugin, httpx_mock):
        """Page with __proto__ pattern → MEDIUM prototype pollution finding."""
        page = """
        <html><body>
        <script>
            function merge(target, source) {
                for (var key in source) {
                    target[key] = source[key];
                    // vulnerable: target.__proto__[key] = source[key]
                }
            }
        </script>
        </body></html>
        """
        httpx_mock.add_response(status_code=200, text=page)
        target = Target(url="https://example.com")
        results = await plugin.run(target)

        assert len(results) >= 1
        finding = next(r for r in results if r.rule_id == "dom_prototype_pollution")
        assert finding.base_severity == Severity.MEDIUM
        assert finding.cwe_id == "CWE-1321"

    @pytest.mark.asyncio
    async def test_postmessage_no_origin(self, plugin, httpx_mock):
        """postMessage listener without origin check → MEDIUM finding."""
        page = """
        <html><body>
        <script>
            window.addEventListener('message', function(e) {
                document.getElementById('out').innerHTML = e.data;
            });
        </script>
        </body></html>
        """
        httpx_mock.add_response(status_code=200, text=page)
        target = Target(url="https://example.com")
        results = await plugin.run(target)

        assert len(results) >= 1
        finding = next(r for r in results if r.rule_id == "dom_postmessage_no_origin")
        assert finding.base_severity == Severity.MEDIUM
        assert finding.cwe_id == "CWE-346"

    @pytest.mark.asyncio
    async def test_clean_page_no_findings(self, plugin, httpx_mock):
        """Clean page with no dangerous JS patterns returns no results."""
        page = """
        <html><body>
        <script>
            document.getElementById('out').textContent = "Hello, world!";
        </script>
        </body></html>
        """
        httpx_mock.add_response(status_code=200, text=page)
        target = Target(url="https://example.com")
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_linked_js_analyzed(self, plugin, httpx_mock):
        """Dangerous patterns in a linked same-domain JS file are detected."""
        page = """
        <html><head>
        <script src="/app.js"></script>
        </head><body></body></html>
        """
        js_content = "var src = location.hash;\ndocument.body.innerHTML = src;"
        # First request: main page; second: the linked JS file
        httpx_mock.add_response(status_code=200, text=page)
        httpx_mock.add_response(status_code=200, text=js_content)

        target = Target(url="https://example.com")
        results = await plugin.run(target)

        assert len(results) >= 1
        rule_ids = {r.rule_id for r in results}
        assert "dom_xss_source_sink" in rule_ids

    @pytest.mark.asyncio
    async def test_no_url_run_returns_empty(self, plugin):
        """run() with no URL returns empty list without making HTTP calls."""
        target = Target(url=None, path="/code", mode="whitebox")
        results = await plugin.run(target)
        assert results == []
