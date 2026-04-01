# tests/plugins/blackbox/test_api_key_exposure.py
"""Tests for API key exposure detection plugin (P2-3)."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.api_key_exposure import ApiKeyExposurePlugin
from vibee_hacker.core.models import Target, Severity


class TestApiKeyExposure:
    @pytest.fixture
    def plugin(self):
        return ApiKeyExposurePlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com")

    @pytest.mark.asyncio
    async def test_stripe_key_in_response(self, plugin, target, httpx_mock):
        """Stripe secret key found directly in HTML response."""
        httpx_mock.add_response(
            url="https://example.com",
            status_code=200,
            text='<html><body>api_key = "sk_test_FAKE_KEY_FOR_UNIT_TESTING_01234567890abcdef"</body></html>',
            headers={"content-type": "text/html"},
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.CRITICAL
        assert "api_key_exposed" in results[0].rule_id
        assert results[0].cwe_id == "CWE-798"

    @pytest.mark.asyncio
    async def test_key_in_linked_js(self, plugin, target, httpx_mock):
        """API key found in a linked JavaScript file."""
        # Main page with script tag
        httpx_mock.add_response(
            url="https://example.com",
            status_code=200,
            text='<html><head><script src="/app.js"></script></head><body>Hello</body></html>',
            headers={"content-type": "text/html"},
        )
        # The JS file with an API key
        httpx_mock.add_response(
            url="https://example.com/app.js",
            status_code=200,
            text='var api_key = "abcdefghijklmnopqrstuv12345";',
            headers={"content-type": "application/javascript"},
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].cwe_id == "CWE-798"

    @pytest.mark.asyncio
    async def test_no_keys_found(self, plugin, target, httpx_mock):
        """Clean HTML response with no keys returns empty results."""
        httpx_mock.add_response(
            url="https://example.com",
            status_code=200,
            text="<html><body><p>Hello world, nothing secret here.</p></body></html>",
            headers={"content-type": "text/html"},
        )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, httpx_mock):
        """TransportError returns empty list."""
        target = Target(url="https://down.example.com")
        httpx_mock.add_exception(
            httpx.ConnectError("connection refused"), is_reusable=True
        )
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_slack_token_in_response(self, plugin, target, httpx_mock):
        """Slack token found in response."""
        httpx_mock.add_response(
            url="https://example.com",
            status_code=200,
            text='config = { token: "xoxb-123456789-abcdefghij" }',
            headers={"content-type": "text/html"},
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert any("slack_token" in r.rule_id for r in results)

    @pytest.mark.asyncio
    async def test_no_url_returns_empty(self, plugin):
        """Plugin without URL returns empty list."""
        target = Target(path="/some/path", mode="whitebox")
        results = await plugin.run(target)
        assert results == []
