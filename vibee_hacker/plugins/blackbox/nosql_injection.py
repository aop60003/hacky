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

        parsed = urlparse(target.url)
        params = parse_qs(parsed.query)
        if not params:
            return []

        if len(params) > MAX_PARAMS:
            params = dict(list(params.items())[:MAX_PARAMS])

        headers = {"Content-Type": "application/json"}

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            # Baseline: GET with original params
            try:
                baseline_resp = await client.get(target.url)
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

            baseline_text = baseline_resp.text

            for param_name, values in params.items():
                for payload in OPERATOR_PAYLOADS:
                    # Build JSON body replacing target param with operator object
                    body: dict = {k: v[0] for k, v in params.items()}
                    body[param_name] = payload

                    try:
                        resp = await client.post(
                            target.url,
                            content=json.dumps(body).encode(),
                            headers=headers,
                        )
                    except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                        continue

                    if len(resp.text) > 1_000_000:
                        continue

                    if resp.status_code == 200 and resp.text != baseline_text:
                        curl_cmd = (
                            f"curl -X POST {shlex.quote(target.url)} "
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
                            endpoint=target.url,
                            param_name=param_name,
                            curl_command=curl_cmd,
                            rule_id="nosql_operator_injection",
                        )]

        return []
