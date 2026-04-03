# tests/plugins/blackbox/test_dns_exfiltration.py
"""Tests for DnsExfiltrationPlugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.dns_exfiltration import DnsExfiltrationPlugin
from vibee_hacker.core.models import Target, Severity


class TestDnsExfiltration:
    @pytest.fixture
    def plugin(self):
        return DnsExfiltrationPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/")

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_dns_tunnel_reference_detected(self, plugin, target, httpx_mock):
        """Response mentioning dnscat/iodine is flagged."""
        httpx_mock.add_response(
            status_code=200,
            text='{"version": "1.0", "info": "DNS tunnel via iodine active on port 53"}',
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.rule_id == "dns_exfiltration_risk"
        assert r.cwe_id == "CWE-200"

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False, assert_all_responses_were_requested=False)
    async def test_clean_responses_no_findings(self, plugin, target, httpx_mock):
        """Normal responses without DNS exfil patterns produce no results."""
        for _ in range(20):
            httpx_mock.add_response(
                status_code=200,
                text='{"status": "ok", "message": "Hello World"}',
            )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport errors return empty results."""
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []
