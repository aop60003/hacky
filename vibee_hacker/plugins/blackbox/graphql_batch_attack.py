# vibee_hacker/plugins/blackbox/graphql_batch_attack.py
"""GraphQL batch attack / batch limiting detection plugin."""

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

BATCH_SIZE = 50
BATCH_QUERY = [{"query": "{ __typename }"} for _ in range(BATCH_SIZE)]


def _base_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _count_results(body: str) -> int:
    """Return number of results if response is a JSON array, else 0."""
    try:
        parsed = json.loads(body)
        if isinstance(parsed, list):
            return len(parsed)
    except (json.JSONDecodeError, TypeError):
        pass
    return 0


class GraphqlBatchAttackPlugin(PluginBase):
    name = "graphql_batch_attack"
    description = "Detect absence of GraphQL batch query limiting (DoS / brute-force amplification risk)"
    category = "blackbox"
    phase = 3
    base_severity = Severity.HIGH
    detection_criteria = f"Batch of {BATCH_SIZE} GraphQL queries returns array of {BATCH_SIZE} results"
    expected_evidence = f"JSON array of {BATCH_SIZE} responses in GraphQL reply"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        base = _base_url(target.url)
        results: list[Result] = []
        payload_str = json.dumps(BATCH_QUERY[:3]) + "... (50 total)"

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=15) as client:
            for path in GRAPHQL_PATHS:
                endpoint = base + path
                try:
                    resp = await client.post(
                        endpoint,
                        json=BATCH_QUERY,
                        headers={"Content-Type": "application/json"},
                    )
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                if resp.status_code not in (200, 201):
                    continue

                if len(resp.text) > 1_000_000:
                    continue

                result_count = _count_results(resp.text)
                if result_count >= BATCH_SIZE:
                    results.append(Result(
                        plugin_name=self.name,
                        base_severity=self.base_severity,
                        title=f"GraphQL no batch limit at {path}",
                        description=(
                            f"The GraphQL endpoint at {endpoint} processed a batch of {BATCH_SIZE} "
                            f"queries in a single request without enforcing batch size limits. "
                            f"This can be exploited for DoS attacks or to amplify brute-force attempts "
                            f"(e.g., credential stuffing via batched login mutations)."
                        ),
                        evidence=(
                            f"Batch of {BATCH_SIZE} queries returned {result_count} results | "
                            f"Path: {path} | Status: {resp.status_code}"
                        ),
                        cwe_id="CWE-770",
                        endpoint=endpoint,
                        curl_command=(
                            f"curl -X POST {shlex.quote(endpoint)} "
                            f"-H 'Content-Type: application/json' "
                            f"-d '[{{\"query\":\"{{ __typename }}\"}}, ...]  # 50 items'"
                        ),
                        rule_id="graphql_no_batch_limit",
                    ))
                    return results  # Stop on first finding

        return results
