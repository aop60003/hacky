# vibee_hacker/plugins/blackbox/nosql_injection.py
"""NoSQL Injection detection plugin (MongoDB operator injection)."""

from __future__ import annotations

import json
import shlex
from urllib.parse import urlparse, parse_qs

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

# MongoDB operator payloads that may bypass authentication
OPERATOR_PAYLOADS = [
    {"$gt": ""},
    {"$ne": ""},
    {"$regex": ".*"},
]

MAX_PARAMS = 10


class NoSqlInjectionPlugin(PluginBase):
    name = "nosql_injection"
    description = "NoSQL Injection detection (MongoDB operator injection)"
    category = "blackbox"
    phase = 3
    base_severity = Severity.CRITICAL
    detection_criteria = "POST with MongoDB operators returns different response than baseline GET"
    expected_evidence = "Different HTTP response body/status when operator payload is submitted"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        # Build list of URLs to test: start URL + crawled URLs that have query params
        urls_to_test: list[str] = [target.url]
        if context:
            for crawled_url in (context.crawl_urls or [])[:20]:
                if crawled_url != target.url and "?" in crawled_url:
                    urls_to_test.append(crawled_url)

        headers = {"Content-Type": "application/json"}

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            for test_target_url in urls_to_test:
                parsed = urlparse(test_target_url)
                params = parse_qs(parsed.query)
                if not params:
                    continue

                capped_params = dict(list(params.items())[:MAX_PARAMS])

                # Build the original (non-injected) body from URL params
                original_body: dict = {k: v[0] for k, v in capped_params.items()}

                # Baseline: POST with original param values as JSON body
                try:
                    baseline_resp = await client.post(test_target_url, json=original_body)
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                baseline_text = baseline_resp.text

                for param_name, values in capped_params.items():
                    for payload in OPERATOR_PAYLOADS:
                        # Build JSON body replacing target param with operator object
                        body: dict = {k: v[0] for k, v in capped_params.items()}
                        body[param_name] = payload

                        try:
                            resp = await client.post(
                                test_target_url,
                                content=json.dumps(body).encode(),
                                headers=headers,
                            )
                        except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                            continue

                        if len(resp.text) > 1_000_000:
                            continue

                        if resp.status_code == 200 and resp.text != baseline_text:
                            curl_cmd = (
                                f"curl -X POST {shlex.quote(test_target_url)} "
                                f"-H 'Content-Type: application/json' "
                                f"-d {shlex.quote(json.dumps(body))}"
                            )
                            return [Result(
                                plugin_name=self.name,
                                base_severity=self.base_severity,
                                title=f"NoSQL Injection in parameter '{param_name}'",
                                description=(
                                    f"MongoDB operator injection detected: payload {json.dumps(payload)!r} "
                                    f"returned a different response than the baseline, indicating "
                                    f"potential authentication bypass."
                                ),
                                evidence=f"payload={json.dumps(payload)} → response differs from baseline",
                                cwe_id="CWE-943",
                                endpoint=test_target_url,
                                param_name=param_name,
                                curl_command=curl_cmd,
                                rule_id="nosql_operator_injection",
                            )]

        return []
