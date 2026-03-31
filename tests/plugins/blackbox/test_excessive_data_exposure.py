# tests/plugins/blackbox/test_excessive_data_exposure.py
"""Tests for excessive data exposure plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.excessive_data_exposure import ExcessiveDataExposurePlugin
from vibee_hacker.core.models import Target, Severity


class TestExcessiveDataExposure:
    @pytest.fixture
    def plugin(self):
        return ExcessiveDataExposurePlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/api/users/1")

    @pytest.mark.asyncio
    async def test_password_field_in_response(self, plugin, target, httpx_mock):
        """JSON response containing 'password' field is reported as HIGH."""
        httpx_mock.add_response(
            url="https://example.com/api/users/1",
            status_code=200,
            json={
                "id": 1,
                "username": "alice",
                "email": "alice@example.com",
                "password": "hashed_password_value",
                "role": "user",
            },
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.HIGH
        assert results[0].rule_id == "excessive_data_exposure"
        assert results[0].cwe_id == "CWE-213"

    @pytest.mark.asyncio
    async def test_clean_response_no_finding(self, plugin, target, httpx_mock):
        """Clean JSON response with no sensitive fields produces no results."""
        httpx_mock.add_response(
            url="https://example.com/api/users/1",
            status_code=200,
            json={
                "id": 1,
                "username": "alice",
                "email": "alice@example.com",
                "role": "user",
            },
        )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_non_json_response_skipped(self, plugin, target, httpx_mock):
        """Non-JSON HTML response is skipped and produces no results."""
        httpx_mock.add_response(
            url="https://example.com/api/users/1",
            status_code=200,
            text="<html><body>password: secret</body></html>",
            headers={"content-type": "text/html"},
        )
        results = await plugin.run(target)
        assert len(results) == 0
