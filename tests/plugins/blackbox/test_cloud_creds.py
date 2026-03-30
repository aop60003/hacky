# tests/plugins/blackbox/test_cloud_creds.py
"""Tests for cloud credentials leak detection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.cloud_creds_leak import CloudCredsPlugin
from vibee_hacker.core.models import Target, Severity


class TestCloudCreds:
    @pytest.fixture
    def plugin(self):
        return CloudCredsPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/")

    @pytest.mark.asyncio
    async def test_aws_key_in_response(self, plugin, target, httpx_mock):
        """AWS key found in response body is reported as CRITICAL."""
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=200,
            text="<html><body>key=AKIAIOSFODNN7EXAMPLE secret=wJalrXUtnFEMI</body></html>",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.CRITICAL
        assert results[0].cwe_id == "CWE-798"
        assert "cloud_creds_" in results[0].rule_id

    @pytest.mark.asyncio
    async def test_github_token_in_response(self, plugin, target, httpx_mock):
        """GitHub token found in response body is reported as CRITICAL."""
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=200,
            text="<html><body>token=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890 rest</body></html>",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.CRITICAL
        assert results[0].cwe_id == "CWE-798"

    @pytest.mark.asyncio
    async def test_no_credentials(self, plugin, target, httpx_mock):
        """Clean response with no credentials returns no results."""
        httpx_mock.add_response(
            url="https://example.com/",
            status_code=200,
            text="<html><body>Welcome, nothing secret here</body></html>",
        )
        results = await plugin.run(target)
        assert len(results) == 0
