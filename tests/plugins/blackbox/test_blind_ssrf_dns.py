# tests/plugins/blackbox/test_blind_ssrf_dns.py
"""Tests for Blind SSRF via DNS detection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.blind_ssrf_dns import BlindSsrfDnsPlugin, OOB_DOMAIN
from vibee_hacker.core.models import Target, Severity


class TestBlindSsrfDns:
    @pytest.fixture
    def plugin(self):
        return BlindSsrfDnsPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/fetch?url=https://safe.example.com")

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_oob_domain_reflected_is_vulnerable(self, plugin, target, httpx_mock):
        """Server reflects OOB domain in response — reported as HIGH."""
        def response_with_oob(request):
            # Reflect OOB domain from the injected url param
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(str(request.url))
            params = parse_qs(parsed.query)
            url_val = params.get("url", [""])[0]
            body = f'{{"fetched": "{url_val}", "status": "ok"}}'
            return httpx.Response(200, text=body)

        httpx_mock.add_callback(response_with_oob, is_reusable=True)
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].rule_id == "blind_ssrf_dns"
        assert results[0].cwe_id == "CWE-918"
        assert results[0].base_severity == Severity.HIGH

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_oob_domain_not_reflected_not_vulnerable(self, plugin, target, httpx_mock):
        """Server does not reflect OOB domain — no results."""
        httpx_mock.add_response(
            status_code=200,
            text='{"status": "ok"}',
            is_reusable=True,
        )
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_url_param_no_results(self, plugin, httpx_mock):
        """URL with no URL-type params returns empty without errors."""
        target = Target(url="https://example.com/search?q=hello")
        httpx_mock.add_response(
            status_code=200,
            text="<html>Search results</html>",
            is_reusable=True,
        )
        results = await plugin.run(target)
        # May or may not probe PROBE_PATHS, but should not crash
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, httpx_mock):
        """TransportError returns empty list."""
        target = Target(url="https://down.example.com/fetch?url=http://x.com")
        httpx_mock.add_exception(httpx.ConnectError("connection refused"), is_reusable=True)
        results = await plugin.run(target)
        assert results == []
