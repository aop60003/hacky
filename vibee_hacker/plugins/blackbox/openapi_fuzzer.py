"""OpenAPI/Swagger specification-based API fuzzer."""

from __future__ import annotations

import re
from urllib.parse import urljoin

import httpx

from vibee_hacker.core.models import Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

SWAGGER_PATHS = [
    "/swagger.json", "/openapi.json", "/api-docs", "/swagger/v1/swagger.json",
    "/v1/swagger.json", "/v2/swagger.json", "/v3/api-docs",
    "/api/swagger.json", "/api/openapi.json", "/.well-known/openapi.json",
]


class OpenapiFuzzerPlugin(PluginBase):
    name = "openapi_fuzzer"
    description = "Discovers and tests API endpoints from OpenAPI/Swagger specs"
    category = "blackbox"
    phase = 2
    destructive_level = 1

    def is_applicable(self, target: Target) -> bool:
        return bool(target.url)

    async def run(self, target: Target, context=None) -> list[Result]:
        if not target.url:
            return []

        results = []
        base_url = target.url.rstrip("/")

        async with httpx.AsyncClient(
            verify=getattr(target, "verify_ssl", True),
            timeout=10,
            follow_redirects=True,
        ) as client:
            # 1. Discover OpenAPI spec
            spec = None
            spec_url = ""
            for path in SWAGGER_PATHS:
                try:
                    resp = await client.get(f"{base_url}{path}")
                    if resp.status_code == 200 and "json" in resp.headers.get("content-type", ""):
                        spec = resp.json()
                        spec_url = f"{base_url}{path}"
                        break
                except Exception:
                    continue

            if not spec:
                return []

            # Report spec exposure
            results.append(Result(
                plugin_name=self.name,
                base_severity=Severity.MEDIUM,
                title=f"OpenAPI/Swagger spec exposed at {spec_url}",
                description="The API specification is publicly accessible, revealing endpoint structure and parameters.",
                endpoint=spec_url,
                rule_id="openapi_spec_exposed",
                cwe_id="CWE-200",
                recommendation="Restrict access to API documentation in production.",
            ))

            # 2. Parse endpoints
            paths = spec.get("paths", {})
            servers = spec.get("servers", [])
            api_base = servers[0]["url"] if servers else base_url

            for endpoint_path, methods in paths.items():
                for method_name, method_spec in methods.items():
                    if method_name not in ("get", "post", "put", "delete", "patch"):
                        continue

                    full_url = urljoin(api_base, endpoint_path)
                    # Replace path params with test values
                    full_url = re.sub(r"\{[^}]+\}", "1", full_url)

                    # 3. Check for auth requirements
                    security = method_spec.get("security", spec.get("security", []))
                    if not security:
                        # No auth required — test for broken access
                        try:
                            resp = await client.request(method_name.upper(), full_url)
                            if resp.status_code == 200:
                                results.append(Result(
                                    plugin_name=self.name,
                                    base_severity=Severity.HIGH,
                                    title=f"Unauthenticated {method_name.upper()} {endpoint_path}",
                                    description=f"API endpoint {endpoint_path} accessible without authentication.",
                                    endpoint=full_url,
                                    rule_id="openapi_no_auth",
                                    cwe_id="CWE-306",
                                    recommendation="Add authentication to all API endpoints.",
                                ))
                        except Exception:
                            continue

                    # 4. Check for sensitive data in parameters
                    parameters = method_spec.get("parameters", [])
                    for param in parameters:
                        param_name = param.get("name", "").lower()
                        if any(s in param_name for s in ["password", "secret", "token", "key", "auth"]):
                            results.append(Result(
                                plugin_name=self.name,
                                base_severity=Severity.MEDIUM,
                                title=f"Sensitive parameter '{param.get('name')}' in {endpoint_path}",
                                description=f"Parameter name suggests sensitive data handling.",
                                endpoint=full_url,
                                param_name=param.get("name"),
                                rule_id="openapi_sensitive_param",
                                cwe_id="CWE-200",
                                recommendation="Ensure sensitive parameters are transmitted securely.",
                            ))

        return results[:20]  # Limit results
