# tests/plugins/blackbox/test_ldap_injection.py
"""Tests for LDAP injection detection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.ldap_injection import LdapInjectionPlugin
from vibee_hacker.core.models import Target, Severity


class TestLdapInjection:
    @pytest.fixture
    def plugin(self):
        return LdapInjectionPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/search?q=admin")

    @pytest.mark.asyncio
    async def test_ldap_error_detected(self, plugin, target, httpx_mock):
        """LDAP error in response body triggers a HIGH finding."""
        # First request returns LDAP error; plugin returns early after first match
        httpx_mock.add_response(
            status_code=200,
            text="Error: LDAP query failed - Bad search filter",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.HIGH
        assert results[0].rule_id == "ldap_injection"
        assert results[0].cwe_id == "CWE-90"

    @pytest.mark.asyncio
    async def test_no_ldap_error(self, plugin, target, httpx_mock):
        """Normal responses produce no results."""
        # 1 param * 3 payloads = 3 requests
        for _ in range(3):
            httpx_mock.add_response(status_code=200, text="normal response")
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_no_params_skipped(self, plugin, httpx_mock):
        """URL with no query params is skipped."""
        target = Target(url="https://example.com/search")
        results = await plugin.run(target)
        assert results == []
