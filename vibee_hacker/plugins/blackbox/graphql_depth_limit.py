# vibee_hacker/plugins/blackbox/graphql_depth_limit.py
"""GraphQL depth limit detection plugin."""

from __future__ import annotations

import json
import re
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

# 10+ levels deep query to trigger depth limit enforcement
DEEP_QUERY = {
    "query": "{ a { b { c { d { e { f { g { h { i { j { name } } } } } } } } } } }"
}

# Patterns that indicate depth limit is enforced (server rejected deep query)
DEPTH_LIMIT_PATTERNS = [
    re.compile(r"max(imum)?\s*depth", re.I),
    re.compile(r"query\s+depth\s+limit", re.I),
    re.compile(r"exceeds\s+.*depth", re.I),
    re.compile(r"depth\s+.*exceeded", re.I),
    re.compile(r"too\s+deep", re.I),
    re.compile(r"complexity\s+limit", re.I),
]


def _base_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _has_data(body: str) -> bool:
    """Return True if body looks like a successful GraphQL data response."""
    try:
        parsed = json.loads(body)
        return "data" in parsed and parsed["data"] is not None
    except (json.JSONDecodeError, TypeError):
        return False


def _has_depth_error(body: str) -> bool:
    """Return True if body contains depth limit enforcement message."""
    return any(p.search(body) for p in DEPTH_LIMIT_PATTERNS)


class GraphqlDepthLimitPlugin(PluginBase):
    name = "graphql_depth_limit"
    description = "Detect absence of GraphQL query depth limiting (DoS risk)"
    category = "blackbox"
    phase = 3
    base_severity = Severity.HIGH
    detection_criteria = "Deep GraphQL query (10+ levels) returns 200 with data (no depth error)"
    expected_evidence = "GraphQL response contains data for deeply nested query without depth error"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        base = _base_url(target.url)
        results: list[Result] = []
        payload_str = json.dumps(DEEP_QUERY)

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            for path in GRAPHQL_PATHS:
                endpoint = base + path
                try:
                    resp = await client.post(
                        endpoint,
                        json=DEEP_QUERY,
                        headers={"Content-Type": "application/json"},
                    )
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                if resp.status_code not in (200, 201):
                    continue

                if len(resp.text) > 1_000_000:
                    continue

                # Vulnerable if server returns data without rejecting the deep query
                if _has_data(resp.text) and not _has_depth_error(resp.text):
                    results.append(Result(
                        plugin_name=self.name,
                        base_severity=self.base_severity,
                        title=f"GraphQL no depth limit at {path}",
                        description=(
                            f"The GraphQL endpoint at {endpoint} processed a 10-level deep query "
                            f"without enforcing a depth limit. Deeply nested queries can cause "
                            f"exponential resource consumption, leading to denial of service."
                        ),
                        evidence=f"Deep query (10+ levels) returned data | Path: {path} | Status: {resp.status_code}",
                        cwe_id="CWE-770",
                        endpoint=endpoint,
                        curl_command=(
                            f"curl -X POST {shlex.quote(endpoint)} "
                            f"-H 'Content-Type: application/json' "
                            f"-d {shlex.quote(payload_str)}"
                        ),
                        rule_id="graphql_no_depth_limit",
                    ))
                    return results  # Stop on first finding

        return results
