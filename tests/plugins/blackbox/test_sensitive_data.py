# tests/plugins/blackbox/test_sensitive_data.py
"""Tests for sensitive data exposure plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.sensitive_data_exposure import SensitiveDataPlugin
from vibee_hacker.core.models import Target, Severity


class TestSensitiveData:
    @pytest.fixture
    def plugin(self):
        return SensitiveDataPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/page")

    @pytest.mark.asyncio
    async def test_credit_card_in_response(self, plugin, target, httpx_mock):
        """Credit card number in response body is reported as HIGH."""
        httpx_mock.add_response(
            url="https://example.com/page",
            status_code=200,
            text="Your card ending in 4111111111111111 has been charged.",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.HIGH
        assert results[0].cwe_id == "CWE-200"
        assert "sensitive_data_" in results[0].rule_id

    @pytest.mark.asyncio
    async def test_aws_key_in_response(self, plugin, target, httpx_mock):
        """AWS access key in response body is reported as HIGH."""
        httpx_mock.add_response(
            url="https://example.com/page",
            status_code=200,
            text="AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE configuration leaked",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.HIGH
        assert results[0].cwe_id == "CWE-200"

    @pytest.mark.asyncio
    async def test_clean_response(self, plugin, target, httpx_mock):
        """Clean response with no sensitive data returns no results."""
        httpx_mock.add_response(
            url="https://example.com/page",
            status_code=200,
            text="<html><body>Welcome to our site</body></html>",
        )
        results = await plugin.run(target)
        assert len(results) == 0
