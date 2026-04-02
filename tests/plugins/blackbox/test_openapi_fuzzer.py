"""Tests for OpenAPI/Swagger fuzzer plugin."""

from __future__ import annotations

import pytest
import httpx

from vibee_hacker.plugins.blackbox.openapi_fuzzer import OpenapiFuzzerPlugin, SWAGGER_PATHS
from vibee_hacker.core.models import Target, Severity


class TestOpenapiFuzzerPlugin:
    @pytest.fixture
    def plugin(self):
        return OpenapiFuzzerPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://api.example.com")

    def test_is_applicable_with_url(self, plugin, target):
        assert plugin.is_applicable(target) is True

    def test_is_applicable_no_url(self, plugin):
        t = Target(path="/some/path", mode="whitebox")
        assert plugin.is_applicable(t) is False

    @pytest.mark.asyncio
    async def test_no_url_returns_empty(self, plugin):
        """Plugin with no URL target returns empty list."""
        t = Target(path="/some/path", mode="whitebox")
        results = await plugin.run(t)
        assert results == []

    @pytest.mark.asyncio
    async def test_spec_exposed(self, plugin, target, httpx_mock):
        """Reports MEDIUM finding when swagger.json is publicly accessible."""
        # swagger.json is at the first path
        spec_path = SWAGGER_PATHS[0]  # /swagger.json
        httpx_mock.add_response(
            url=f"https://api.example.com{spec_path}",
            status_code=200,
            headers={"content-type": "application/json"},
            json={
                "openapi": "3.0.0",
                "paths": {},
            },
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        exposure = results[0]
        assert exposure.rule_id == "openapi_spec_exposed"
        assert exposure.base_severity == Severity.MEDIUM
        assert exposure.cwe_id == "CWE-200"
        assert spec_path in exposure.endpoint

    @pytest.mark.asyncio
    async def test_no_spec_found(self, plugin, target, httpx_mock):
        """No results when all spec paths return 404."""
        for path in SWAGGER_PATHS:
            httpx_mock.add_response(
                url=f"https://api.example.com{path}",
                status_code=404,
                text="Not Found",
            )
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_unauthenticated_endpoint(self, plugin, target, httpx_mock):
        """Reports HIGH finding for endpoints with no security and HTTP 200 response."""
        spec_path = SWAGGER_PATHS[0]
        httpx_mock.add_response(
            url=f"https://api.example.com{spec_path}",
            status_code=200,
            headers={"content-type": "application/json"},
            json={
                "openapi": "3.0.0",
                "paths": {
                    "/users": {
                        "get": {
                            "summary": "List users",
                            # no 'security' key — unauthenticated
                        }
                    }
                },
            },
        )
        # Mock the probe request to the endpoint
        httpx_mock.add_response(
            url="https://api.example.com/users",
            method="GET",
            status_code=200,
            json={"users": []},
        )
        results = await plugin.run(target)
        rule_ids = [r.rule_id for r in results]
        assert "openapi_no_auth" in rule_ids
        no_auth = next(r for r in results if r.rule_id == "openapi_no_auth")
        assert no_auth.base_severity == Severity.HIGH
        assert no_auth.cwe_id == "CWE-306"

    @pytest.mark.asyncio
    async def test_sensitive_param(self, plugin, target, httpx_mock):
        """Reports MEDIUM finding for endpoints with sensitive-sounding parameters."""
        spec_path = SWAGGER_PATHS[0]
        httpx_mock.add_response(
            url=f"https://api.example.com{spec_path}",
            status_code=200,
            headers={"content-type": "application/json"},
            json={
                "openapi": "3.0.0",
                # Global security means endpoint IS authenticated, no probe needed
                "security": [{"bearerAuth": []}],
                "paths": {
                    "/login": {
                        "post": {
                            "summary": "Login",
                            "security": [{"bearerAuth": []}],
                            "parameters": [
                                {"name": "password", "in": "query"},
                                {"name": "username", "in": "query"},
                            ],
                        }
                    }
                },
            },
        )
        results = await plugin.run(target)
        rule_ids = [r.rule_id for r in results]
        assert "openapi_sensitive_param" in rule_ids
        sensitive = next(r for r in results if r.rule_id == "openapi_sensitive_param")
        assert sensitive.base_severity == Severity.MEDIUM
        assert sensitive.param_name == "password"

    @pytest.mark.asyncio
    async def test_transport_error_on_spec_returns_empty(self, plugin, target, httpx_mock):
        """Network errors when probing all spec paths returns empty."""
        for path in SWAGGER_PATHS:
            httpx_mock.add_exception(httpx.ConnectError("timeout"))
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_results_limited_to_20(self, plugin, target, httpx_mock):
        """Plugin caps results at 20 even with many endpoints."""
        # Build a spec with 25 unauthenticated endpoints
        paths_dict = {}
        for i in range(25):
            paths_dict[f"/resource{i}"] = {"get": {"summary": f"Resource {i}"}}

        spec_path = SWAGGER_PATHS[0]
        httpx_mock.add_response(
            url=f"https://api.example.com{spec_path}",
            status_code=200,
            headers={"content-type": "application/json"},
            json={"openapi": "3.0.0", "paths": paths_dict},
        )
        # All 25 endpoint probes return 200
        for i in range(25):
            httpx_mock.add_response(
                url=f"https://api.example.com/resource{i}",
                method="GET",
                status_code=200,
                json={},
            )
        results = await plugin.run(target)
        assert len(results) <= 20
