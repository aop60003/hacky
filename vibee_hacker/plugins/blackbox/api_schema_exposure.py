# vibee_hacker/plugins/blackbox/api_schema_exposure.py
"""API schema/documentation exposure detection plugin."""

from __future__ import annotations

import shlex
from urllib.parse import urlparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

SCHEMA_PATHS = [
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/swagger-ui.html",
    "/redoc",
    "/api/swagger.json",
    "/api/openapi.json",
    "/v1/swagger.json",
    "/v2/swagger.json",
]

SCHEMA_INDICATORS = ["paths", "openapi", "swagger", "info", "definitions"]


def _base_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


class ApiSchemaExposurePlugin(PluginBase):
    name = "api_schema_exposure"
    description = "Detect publicly accessible API documentation/schema endpoints"
    category = "blackbox"
    phase = 2
    base_severity = Severity.MEDIUM
    detection_criteria = "API schema endpoint returns 200 with OpenAPI/Swagger content without authentication"
    expected_evidence = "200 response with 'paths' or 'openapi' key in JSON from schema endpoint"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        base = _base_url(target.url)
        results: list[Result] = []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            for path in SCHEMA_PATHS:
                endpoint = base + path
                try:
                    resp = await client.get(endpoint)
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                if resp.status_code != 200:
                    continue

                # Check if response looks like an API schema
                is_json = "application/json" in resp.headers.get("content-type", "")
                body_lower = resp.text.lower() if len(resp.text) < 1_000_000 else ""

                schema_found = False
                if is_json:
                    try:
                        data = resp.json()
                        if isinstance(data, dict):
                            for indicator in SCHEMA_INDICATORS:
                                if indicator in data:
                                    schema_found = True
                                    break
                    except Exception:
                        pass

                # Also check body text for HTML-served swagger UI
                if not schema_found and path.endswith(".html"):
                    if "swagger" in body_lower or "openapi" in body_lower:
                        schema_found = True

                if schema_found:
                    results.append(Result(
                        plugin_name=self.name,
                        base_severity=self.base_severity,
                        title="API schema publicly accessible",
                        description=(
                            f"The API documentation/schema is publicly accessible at {endpoint} "
                            f"without authentication. This exposes all API endpoints, parameters, "
                            f"and data models to potential attackers."
                        ),
                        evidence=(
                            f"GET {endpoint} returned HTTP {resp.status_code} with API schema content"
                        ),
                        recommendation=(
                            "Restrict access to API documentation in production environments. "
                            "Require authentication or IP allowlisting to access swagger/openapi endpoints."
                        ),
                        cwe_id="CWE-200",
                        endpoint=endpoint,
                        curl_command=f"curl -s {shlex.quote(endpoint)}",
                        rule_id="api_schema_public",
                    ))
                    return results  # Stop on first finding

        return results
