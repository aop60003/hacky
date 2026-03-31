# vibee_hacker/plugins/blackbox/graphql_injection.py
"""GraphQL SQL/NoSQL injection detection plugin."""

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

SQL_ERROR_PATTERNS = [
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning.*mysql", re.I),
    re.compile(r"unclosed quotation mark", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"sql syntax.*error", re.I),
    re.compile(r"microsoft.*odbc.*driver", re.I),
    re.compile(r"ORA-\d{5}", re.I),
    re.compile(r"postgresql.*error", re.I),
    re.compile(r"sqlite3?\.OperationalError", re.I),
    re.compile(r"pg_query\(\).*failed", re.I),
    re.compile(r"MongoError", re.I),
    re.compile(r"CastError", re.I),
]

PAYLOADS = [
    {"query": '{ user(id: "1\' OR \'1\'=\'1") { name } }'},
    {"query": '{ user(id: "1; DROP TABLE--") { name } }'},
]


def _base_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


class GraphqlInjectionPlugin(PluginBase):
    name = "graphql_injection"
    description = "Detect SQL/NoSQL injection vulnerabilities via GraphQL endpoints"
    category = "blackbox"
    phase = 3
    base_severity = Severity.CRITICAL
    detection_criteria = "SQL/NoSQL error patterns in GraphQL response after injecting payloads"
    expected_evidence = "SQL/NoSQL error message in GraphQL HTTP response body"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        base = _base_url(target.url)
        results: list[Result] = []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            for path in GRAPHQL_PATHS:
                endpoint = base + path
                for payload in PAYLOADS:
                    try:
                        resp = await client.post(
                            endpoint,
                            json=payload,
                            headers={"Content-Type": "application/json"},
                        )
                    except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                        continue

                    if resp.status_code == 404:
                        continue

                    if len(resp.text) > 1_000_000:
                        continue

                    for pattern in SQL_ERROR_PATTERNS:
                        if pattern.search(resp.text):
                            payload_str = json.dumps(payload)
                            results.append(Result(
                                plugin_name=self.name,
                                base_severity=self.base_severity,
                                title=f"GraphQL SQL/NoSQL injection at {path}",
                                description=(
                                    f"SQL/NoSQL injection detected via GraphQL endpoint {endpoint}. "
                                    f"The server returned a database error message in response to "
                                    f"an injection payload, indicating unsanitized input processing."
                                ),
                                evidence=f"Pattern '{pattern.pattern}' matched in response | Path: {path}",
                                cwe_id="CWE-89",
                                endpoint=endpoint,
                                curl_command=(
                                    f"curl -X POST {shlex.quote(endpoint)} "
                                    f"-H 'Content-Type: application/json' "
                                    f"-d {shlex.quote(payload_str)}"
                                ),
                                rule_id="graphql_sql_injection",
                            ))
                            return results  # Stop on first confirmed finding

        return results
