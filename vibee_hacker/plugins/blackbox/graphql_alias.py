# vibee_hacker/plugins/blackbox/graphql_alias.py
"""GraphQL Alias Overloading detection plugin — rate-limit bypass via aliases."""

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

ALIAS_COUNT = 100


def _base_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _build_alias_query(count: int) -> str:
    """Build a GraphQL query with `count` aliases for __typename."""
    aliases = "\n  ".join(f"a{i}: __typename" for i in range(count))
    return f"{{ {aliases} }}"


def _count_alias_results(body: str, count: int) -> bool:
    """Return True if the response JSON contains at least `count` alias keys."""
    try:
        parsed = json.loads(body)
        data = parsed.get("data") if isinstance(parsed, dict) else None
        if isinstance(data, dict):
            alias_keys = [k for k in data if k.startswith("a") and k[1:].isdigit()]
            return len(alias_keys) >= count
    except (json.JSONDecodeError, TypeError, AttributeError):
        pass
    return False


class GraphqlAliasPlugin(PluginBase):
    name = "graphql_alias"
    description = (
        f"GraphQL Alias Overloading — send {ALIAS_COUNT} aliases in one query "
        f"to test if the server enforces rate limiting or alias limits"
    )
    category = "blackbox"
    phase = 3
    base_severity = Severity.HIGH
    destructive_level = 1
    detection_criteria = (
        f"GraphQL endpoint returns data for all {ALIAS_COUNT} aliases without restriction"
    )
    expected_evidence = f"Response JSON data object contains {ALIAS_COUNT} aliased fields"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        base = _base_url(target.url)
        alias_query = _build_alias_query(ALIAS_COUNT)
        payload = {"query": alias_query}

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=20) as client:
            for path in GRAPHQL_PATHS:
                endpoint = base + path
                try:
                    resp = await client.post(
                        endpoint,
                        json=payload,
                        headers={"Content-Type": "application/json"},
                    )
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                if resp.status_code not in (200, 201):
                    continue

                if len(resp.text) > 2_000_000:
                    continue

                if _count_alias_results(resp.text, ALIAS_COUNT):
                    return [Result(
                        plugin_name=self.name,
                        base_severity=self.base_severity,
                        title=f"GraphQL alias overloading accepted at {path}",
                        description=(
                            f"The GraphQL endpoint at {endpoint} processed a query containing "
                            f"{ALIAS_COUNT} aliases in a single request without enforcing alias "
                            f"limits. Attackers can abuse this to bypass per-request rate limits "
                            f"(e.g., send 100 login attempts in a single GraphQL query via aliases)."
                        ),
                        evidence=(
                            f"{ALIAS_COUNT} aliases returned in single response | "
                            f"Path: {path} | Status: {resp.status_code}"
                        ),
                        cwe_id="CWE-770",
                        endpoint=endpoint,
                        curl_command=(
                            f"curl -X POST {shlex.quote(endpoint)} "
                            f"-H 'Content-Type: application/json' "
                            f"-d '{{\"query\":\"{{ a0: __typename a1: __typename ... "
                            f"({ALIAS_COUNT} total) }}\"}}'  "
                        ),
                        rule_id="graphql_alias_overload",
                    )]

        return []
