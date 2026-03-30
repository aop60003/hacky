# vibee_hacker/plugins/blackbox/prototype_pollution.py
"""Prototype pollution detection plugin."""

from __future__ import annotations

import json
import shlex

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

PAYLOADS = [
    {"__proto__": {"polluted": True}},
    {"constructor": {"prototype": {"polluted": True}}},
]

POLLUTION_INDICATORS = [
    "polluted",
    "Cannot set property",
    "prototype",
    "TypeError",
]


class PrototypePollutionPlugin(PluginBase):
    name = "prototype_pollution"
    description = "Detect prototype pollution vulnerabilities via JSON POST payloads"
    category = "blackbox"
    phase = 3
    base_severity = Severity.HIGH
    detection_criteria = "Server returns 500 or pollution indicators after __proto__ injection"
    expected_evidence = "500 status code or 'polluted'/'TypeError' in response after prototype pollution payload"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        results: list[Result] = []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            for payload in PAYLOADS:
                try:
                    resp = await client.post(
                        target.url,
                        json=payload,
                        headers={"Content-Type": "application/json"},
                    )
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                if len(resp.text) > 1_000_000:
                    continue

                is_server_error = resp.status_code == 500
                body_indicates_pollution = any(
                    indicator in resp.text for indicator in POLLUTION_INDICATORS
                )

                if is_server_error or body_indicates_pollution:
                    payload_str = json.dumps(payload)
                    results.append(Result(
                        plugin_name=self.name,
                        base_severity=self.base_severity,
                        title="Potential prototype pollution vulnerability",
                        description=(
                            f"The application returned an anomalous response (status {resp.status_code}) "
                            f"after receiving a prototype pollution payload. This may indicate the server "
                            f"processes __proto__ or constructor.prototype assignments unsafely."
                        ),
                        evidence=(
                            f"Payload: {payload_str} | "
                            f"Status: {resp.status_code} | "
                            f"Response snippet: {resp.text[:200]}"
                        ),
                        cwe_id="CWE-1321",
                        endpoint=target.url,
                        curl_command=(
                            f"curl -X POST {shlex.quote(target.url)} "
                            f"-H 'Content-Type: application/json' "
                            f"-d {shlex.quote(payload_str)}"
                        ),
                        rule_id="prototype_pollution",
                    ))
                    return results  # Stop on first finding

        return results
