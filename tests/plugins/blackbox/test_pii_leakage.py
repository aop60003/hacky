# tests/plugins/blackbox/test_pii_leakage.py
"""Tests for PII leakage detection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.pii_leakage import PiiLeakagePlugin
from vibee_hacker.core.models import Target, Severity


class TestPiiLeakage:
    @pytest.fixture
    def plugin(self):
        return PiiLeakagePlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/api/profile")

    @pytest.mark.asyncio
    async def test_email_found_in_json(self, plugin, target, httpx_mock):
        """Email address found in JSON response is reported as HIGH."""
        httpx_mock.add_response(
            url="https://example.com/api/profile",
            status_code=200,
            json={
                "id": 42,
                "contact": "alice@example.com",
                "name": "Alice",
            },
            headers={"content-type": "application/json"},
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.HIGH
        assert "pii" in results[0].rule_id
        assert results[0].cwe_id == "CWE-359"

    @pytest.mark.asyncio
    async def test_no_pii_in_response(self, plugin, target, httpx_mock):
        """Response with no PII patterns produces no results."""
        httpx_mock.add_response(
            url="https://example.com/api/profile",
            status_code=200,
            json={"id": 42, "name": "Alice", "role": "user"},
            headers={"content-type": "application/json"},
        )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_html_page_skipped(self, plugin, target, httpx_mock):
        """HTML page response is skipped even if it contains PII-like text."""
        httpx_mock.add_response(
            url="https://example.com/api/profile",
            status_code=200,
            text="<html><body>Contact us at test@example.com for info.</body></html>",
            headers={"content-type": "text/html"},
        )
        results = await plugin.run(target)
        assert len(results) == 0
