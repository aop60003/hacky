# vibee_hacker/plugins/blackbox/api_discovery.py
"""API endpoint discovery plugin."""

from __future__ import annotations

import shlex
from urllib.parse import urlparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

API_PATHS = [
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/swagger-ui.html",
    "/graphql",
    "/v1/graphql",
    "/.well-known/openapi",
]

# Patterns that suggest API documentation content
API_CONTENT_PATTERNS = [
    '"swagger"',
    '"openapi"',
    '"paths"',
    '"info"',
    'swagger-ui',
    '__schema',
    '"query"',
]


def _base_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


class ApiDiscoveryPlugin(PluginBase):
    name = "api_discovery"
    description = "Probe common API documentation paths to discover exposed API endpoints"
    category = "blackbox"
    phase = 1
    base_severity = Severity.INFO
    detection_criteria = "API documentation path returns 200 with JSON content or known API patterns"
    expected_evidence = "HTTP 200 response at a standard API documentation path"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        base = _base_url(target.url)
        results: list[Result] = []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            for path in API_PATHS:
                endpoint = base + path
                try:
                    resp = await client.get(endpoint)
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                if resp.status_code != 200:
                    continue

                if len(resp.text) > 1_000_000:
                    continue

                content_type = resp.headers.get("content-type", "")
                body = resp.text

                is_api_doc = (
                    "application/json" in content_type
                    or "application/yaml" in content_type
                    or any(pattern in body for pattern in API_CONTENT_PATTERNS)
                )

                if is_api_doc:
                    results.append(Result(
                        plugin_name=self.name,
                        base_severity=self.base_severity,
                        title=f"API documentation endpoint discovered: {path}",
                        description=(
                            f"An API documentation endpoint is accessible at {endpoint}. "
                            f"This may expose API structure, parameters, and authentication requirements."
                        ),
                        evidence=f"Path: {path} | Status: {resp.status_code} | Content-Type: {content_type}",
                        cwe_id=None,
                        endpoint=endpoint,
                        curl_command=f"curl {shlex.quote(endpoint)}",
                        rule_id="api_endpoint_discovered",
                    ))
                    return results  # Stop on first finding

        return results
