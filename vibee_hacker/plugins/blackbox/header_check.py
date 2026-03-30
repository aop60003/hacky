# vibee_hacker/plugins/blackbox/header_check.py
"""Security header check plugin."""

from __future__ import annotations

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

REQUIRED_HEADERS = {
    "Content-Security-Policy": "CSP prevents XSS and data injection attacks",
    "X-Frame-Options": "Prevents clickjacking by controlling iframe embedding",
    "X-Content-Type-Options": "Prevents MIME type sniffing",
    "Strict-Transport-Security": "Enforces HTTPS connections",
    "Referrer-Policy": "Controls referrer information leakage",
    "Permissions-Policy": "Controls browser feature permissions",
}


class HeaderCheckPlugin(PluginBase):
    name = "header_check"
    description = "Check for missing security headers"
    category = "blackbox"
    phase = 2
    base_severity = Severity.MEDIUM
    detection_criteria = "HTTP response missing recommended security headers"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            try:
                resp = await client.get(target.url)
            except httpx.TransportError:
                return []

        results = []
        resp_headers = {k.lower(): v for k, v in resp.headers.items()}

        for header, reason in REQUIRED_HEADERS.items():
            if header.lower() not in resp_headers:
                results.append(Result(
                    plugin_name=self.name,
                    base_severity=self.base_severity,
                    title=f"Missing header: {header}",
                    description=f"{header} header is not set. {reason}.",
                    recommendation=f"Add the {header} header to HTTP responses.",
                    endpoint=target.url,
                    rule_id=f"header_missing_{header.lower().replace('-', '_')}",
                ))

        return results
