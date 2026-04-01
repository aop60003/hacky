# tests/plugins/blackbox/test_ssrf.py
"""Tests for the SSRF detection plugin."""

import pytest
import httpx

from vibee_hacker.plugins.blackbox.ssrf import SsrfPlugin
from vibee_hacker.core.models import Target, Severity


class TestSsrfPlugin:
    @pytest.fixture
    def plugin(self):
        return SsrfPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/fetch?url=https://example.com")

    # --- Positive detection tests ---

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_responses_were_requested=False)
    async def test_ssrf_aws_metadata_detected(self, plugin, target, httpx_mock):
        """SSRF payload returns AWS EC2 metadata - must flag CRITICAL."""
        # Baseline response: normal page
        httpx_mock.add_response(
            url="https://example.com/fetch?url=https://example.com",
            text="<html>Normal page</html>",
        )
        # Payload response: AWS metadata leaked
        httpx_mock.add_response(
            text="ami-0abcdef1234567890\ninstance-id: i-1234567890abcdef0",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].rule_id == "ssrf_internal_access"
        assert results[0].base_severity == Severity.CRITICAL
        assert results[0].cwe_id == "CWE-918"
        assert results[0].param_name == "url"

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_responses_were_requested=False)
    async def test_ssrf_localhost_page_content(self, plugin, target, httpx_mock):
        """SSRF payload returns internal localhost page title - must flag CRITICAL."""
        httpx_mock.add_response(
            url="https://example.com/fetch?url=https://example.com",
            text="<html><title>Public Site</title></html>",
        )
        httpx_mock.add_response(
            text="<html><title>localhost admin panel</title></html>",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].rule_id == "ssrf_internal_access"

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_responses_were_requested=False)
    async def test_ssrf_etc_passwd_returned(self, plugin, target, httpx_mock):
        """SSRF causes /etc/passwd content to be returned."""
        httpx_mock.add_response(
            url="https://example.com/fetch?url=https://example.com",
            text="<html>Normal page</html>",
        )
        httpx_mock.add_response(
            text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.CRITICAL

    # --- Negative tests ---

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_responses_were_requested=False)
    async def test_no_ssrf_identical_response(self, plugin, target, httpx_mock):
        """If all responses are identical to baseline, no SSRF is flagged."""
        normal_body = "<html>Normal page nothing internal here</html>"
        # Return the same normal page for baseline + all payloads (1 + 10 = 11)
        for _ in range(11):
            httpx_mock.add_response(text=normal_body)
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_responses_were_requested=False)
    async def test_no_ssrf_different_but_safe_response(self, plugin, target, httpx_mock):
        """Different response content but no internal data patterns - no finding."""
        httpx_mock.add_response(
            url="https://example.com/fetch?url=https://example.com",
            text="<html>Normal page</html>",
        )
        # Different but safe responses (no metadata patterns), one per payload
        for _ in range(10):
            httpx_mock.add_response(text="<html>Error: invalid URL scheme</html>")
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_no_params_returns_empty(self, plugin, httpx_mock):
        """URL with no query parameters - plugin returns empty immediately."""
        target = Target(url="https://example.com/page")
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_url_returns_empty(self, plugin):
        """Target with no URL - plugin returns empty immediately."""
        target = Target(path="/some/local/path")
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_transport_error_on_baseline_returns_empty(self, plugin, target, httpx_mock):
        """If baseline request fails with TransportError, return empty."""
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_responses_were_requested=False)
    async def test_transport_error_on_payload_continues(self, plugin, target, httpx_mock):
        """If a payload request fails, it should be skipped (not crash)."""
        httpx_mock.add_response(
            url="https://example.com/fetch?url=https://example.com",
            text="<html>Normal page</html>",
        )
        # All payload requests fail (10 payloads now)
        for _ in range(10):
            httpx_mock.add_exception(httpx.ConnectTimeout("timed out"))
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_responses_were_requested=False)
    async def test_max_params_limit(self, plugin, httpx_mock):
        """Only first MAX_PARAMS=10 parameters are tested."""
        # Build URL with 15 params
        params = "&".join(f"p{i}=v{i}" for i in range(15))
        target = Target(url=f"https://example.com/page?{params}")
        # Register enough responses: 1 baseline + MAX_PARAMS(10) * len(SSRF_PAYLOADS)(10) = 101
        # Use 110 to have a safe margin; excess unused ones are tolerated (assert_all_responses_were_requested=False)
        for _ in range(110):
            httpx_mock.add_response(text="<html>Safe</html>")
        results = await plugin.run(target)
        assert results == []
