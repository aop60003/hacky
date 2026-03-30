# vibee_hacker/plugins/blackbox/graphql_introspection.py
"""GraphQL introspection detection plugin."""

from __future__ import annotations

import json
import shlex
from urllib.parse import urlparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

GRAPHQL_PATHS = [
    "/graphql",
    "/gql",
    "/api/graphql",
]

INTROSPECTION_QUERY = {"query": "{ __schema { types { name } } }"}


def _base_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


class GraphqlIntrospectionPlugin(PluginBase):
    name = "graphql_introspection"
    description = "Detect enabled GraphQL introspection which exposes API schema"
    category = "blackbox"
    phase = 2
    base_severity = Severity.HIGH
    detection_criteria = "GraphQL introspection query returns __schema with types"
    expected_evidence = "__schema and types present in GraphQL response body"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        base = _base_url(target.url)
        results: list[Result] = []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            for path in GRAPHQL_PATHS:
                endpoint = base + path
                try:
                    resp = await client.post(
                        endpoint,
                        json=INTROSPECTION_QUERY,
                        headers={"Content-Type": "application/json"},
                    )
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                if resp.status_code not in (200, 201):
                    continue

                if len(resp.text) > 1_000_000:
                    continue

                body = resp.text
                if "__schema" in body and "types" in body:
                    payload_str = json.dumps(INTROSPECTION_QUERY)
                    results.append(Result(
                        plugin_name=self.name,
                        base_severity=self.base_severity,
                        title=f"GraphQL introspection enabled: {path}",
                        description=(
                            f"GraphQL introspection is enabled at {endpoint}. "
                            f"This allows attackers to enumerate the entire API schema, "
                            f"discover all types, queries, mutations, and their arguments."
                        ),
                        evidence=f"Path: {path} | __schema and types found in introspection response",
                        cwe_id="CWE-200",
                        endpoint=endpoint,
                        curl_command=(
                            f"curl -X POST {shlex.quote(endpoint)} "
                            f"-H 'Content-Type: application/json' "
                            f"-d {shlex.quote(payload_str)}"
                        ),
                        rule_id="graphql_introspection_enabled",
                    ))
                    return results  # Stop on first finding

        return results
