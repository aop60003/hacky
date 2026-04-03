"""Tests for business logic vulnerability detection plugin."""

from __future__ import annotations

import pytest
import httpx

from vibee_hacker.plugins.blackbox.business_logic import BusinessLogicPlugin
from vibee_hacker.core.models import Target, Severity


@pytest.fixture
def plugin():
    return BusinessLogicPlugin()


class TestBusinessLogicApplicability:
    def test_is_applicable(self, plugin):
        target = Target(url="https://example.com/checkout?price=100")
        assert plugin.is_applicable(target) is True

    def test_not_applicable_no_url(self, plugin):
        target = Target(url=None, path="/some/path", mode="whitebox")
        assert plugin.is_applicable(target) is False


class TestBusinessLogicDetection:
    @pytest.mark.asyncio
    async def test_numeric_tampering_detected(self, plugin, httpx_mock):
        """Tampered price value reflected in 200 response triggers a finding."""
        # The plugin tries "0" first; respond with 200 containing "0" in body
        httpx_mock.add_response(
            status_code=200,
            text='{"total": 0, "status": "ok"}',
        )
        target = Target(url="https://example.com/checkout?price=100")
        results = await plugin.run(target)

        assert len(results) >= 1
        finding = results[0]
        assert finding.rule_id == "biz_numeric_tampering"
        assert finding.base_severity == Severity.HIGH
        assert finding.cwe_id == "CWE-20"
        assert "price" in finding.title.lower()

    @pytest.mark.asyncio
    async def test_privilege_escalation_detected(self, plugin, httpx_mock):
        """Role param escalated to 'admin' and server returns 200 triggers a finding."""
        httpx_mock.add_response(status_code=200, text="Welcome, admin!")
        target = Target(url="https://example.com/dashboard?role=user")
        results = await plugin.run(target)

        assert len(results) >= 1
        finding = results[0]
        assert finding.rule_id == "biz_privilege_escalation"
        assert finding.base_severity == Severity.CRITICAL
        assert finding.cwe_id == "CWE-269"

    @pytest.mark.asyncio
    async def test_workflow_bypass_detected(self, plugin, httpx_mock):
        """Status param bypassed to 'completed' and server returns 200 triggers a finding."""
        httpx_mock.add_response(status_code=200, text="Order processed")
        target = Target(url="https://example.com/order?status=pending")
        results = await plugin.run(target)

        assert len(results) >= 1
        finding = results[0]
        assert finding.rule_id == "biz_workflow_bypass"
        assert finding.base_severity == Severity.HIGH
        assert finding.cwe_id == "CWE-841"

    @pytest.mark.asyncio
    async def test_no_sensitive_params(self, plugin, httpx_mock):
        """URL with no sensitive params produces no results without making requests."""
        target = Target(url="https://example.com/search?q=shoes&page=2")
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_transport_error_graceful(self, plugin, httpx_mock):
        """Network errors are swallowed and return empty results."""
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        target = Target(url="https://example.com/checkout?price=100")
        # Should not raise
        results = await plugin.run(target)
        assert isinstance(results, list)

    def test_param_detection_helpers(self, plugin):
        """Unit test for parameter classification helpers."""
        # Numeric
        assert plugin._is_numeric_param("price") is True
        assert plugin._is_numeric_param("total_amount") is True
        assert plugin._is_numeric_param("user_id") is False

        # Role
        assert plugin._is_role_param("role") is True
        assert plugin._is_role_param("user_type") is True
        assert plugin._is_role_param("username") is False

        # State
        assert plugin._is_state_param("status") is True
        assert plugin._is_state_param("approval_state") is True
        assert plugin._is_state_param("color") is False

        # Sensitive (union)
        assert plugin._is_sensitive_param("price") is True
        assert plugin._is_sensitive_param("role") is True
        assert plugin._is_sensitive_param("status") is True
        assert plugin._is_sensitive_param("foo") is False
