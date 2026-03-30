# vibee_hacker/plugins/blackbox/host_header_injection.py
"""Host header injection detection plugin."""

from __future__ import annotations

import shlex

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

EVIL_HOST = "evil.com"


class HostHeaderInjectionPlugin(PluginBase):
    name = "host_header_injection"
    description = "Detect host header injection by checking if injected host is reflected in response"
    category = "blackbox"
    phase = 3
    base_severity = Severity.HIGH
    detection_criteria = "Injected Host/X-Forwarded-Host value reflected in response body or headers"
    expected_evidence = "evil.com found in response body or Location header after Host header injection"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        results: list[Result] = []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            try:
                resp = await client.get(
                    target.url,
                    headers={
                        "Host": EVIL_HOST,
                        "X-Forwarded-Host": EVIL_HOST,
                    },
                )
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

            if len(resp.text) > 1_000_000:
                return []

            # Check if evil.com is reflected in response body
            body_reflected = EVIL_HOST in resp.text

            # Check if evil.com is reflected in relevant response headers
            location_header = resp.headers.get("location", "")
            header_reflected = EVIL_HOST in location_header

            if body_reflected or header_reflected:
                evidence_location = "response body" if body_reflected else "Location header"
                results.append(Result(
                    plugin_name=self.name,
                    base_severity=self.base_severity,
                    title="Host header injection - injected host reflected in response",
                    description=(
                        f"The application reflects the injected Host header value '{EVIL_HOST}' "
                        f"in the {evidence_location}. This can be exploited for password reset poisoning, "
                        f"cache poisoning, or open redirects."
                    ),
                    evidence=f"'{EVIL_HOST}' reflected in {evidence_location} | Status: {resp.status_code}",
                    cwe_id="CWE-644",
                    endpoint=target.url,
                    curl_command=(
                        f"curl {shlex.quote(target.url)} "
                        f"-H 'Host: {EVIL_HOST}' "
                        f"-H 'X-Forwarded-Host: {EVIL_HOST}'"
                    ),
                    rule_id="host_header_reflected",
                ))

        return results
