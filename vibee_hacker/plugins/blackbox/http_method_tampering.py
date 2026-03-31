# vibee_hacker/plugins/blackbox/http_method_tampering.py
"""HTTP method override/tampering detection plugin."""

from __future__ import annotations

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

OVERRIDE_HEADERS = [
    ("X-HTTP-Method-Override", "DELETE"),
    ("X-Method-Override", "PUT"),
]


class HttpMethodTamperingPlugin(PluginBase):
    name = "http_method_tampering"
    description = "Detect HTTP method override acceptance via X-HTTP-Method-Override / X-Method-Override headers"
    category = "blackbox"
    phase = 3
    base_severity = Severity.MEDIUM
    detection_criteria = "POST with method override header produces a different response than a plain POST"
    expected_evidence = "Response body/status differs when override header is present"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        results: list[Result] = []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10, follow_redirects=True) as client:
            # Baseline: plain POST
            try:
                baseline = await client.post(target.url)
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

            baseline_body = baseline.text
            baseline_status = baseline.status_code

            for header_name, method_value in OVERRIDE_HEADERS:
                try:
                    resp = await client.post(
                        target.url,
                        headers={header_name: method_value},
                    )
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                # Detect if response differs (body or status code changed)
                body_changed = resp.text != baseline_body
                status_changed = resp.status_code != baseline_status

                if body_changed or status_changed:
                    results.append(Result(
                        plugin_name=self.name,
                        base_severity=Severity.MEDIUM,
                        title=f"HTTP method override accepted: {header_name}: {method_value}",
                        description=(
                            f"The server processed the {header_name}: {method_value} header, "
                            f"producing a different response than a plain POST. "
                            f"This may allow unauthorized method execution (e.g. DELETE, PUT) "
                            f"via POST requests."
                        ),
                        evidence=(
                            f"Baseline POST -> {baseline_status} ({len(baseline_body)} bytes); "
                            f"POST with {header_name}: {method_value} -> "
                            f"{resp.status_code} ({len(resp.text)} bytes)"
                        ),
                        recommendation=(
                            "Disable or restrict method override headers in your web framework. "
                            "Do not trust client-supplied method override headers unless explicitly required."
                        ),
                        cwe_id="CWE-16",
                        endpoint=target.url,
                        rule_id="http_method_override_accepted",
                    ))

        return results
