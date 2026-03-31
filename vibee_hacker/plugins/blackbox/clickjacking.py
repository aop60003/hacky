# vibee_hacker/plugins/blackbox/clickjacking.py
"""Clickjacking protection check plugin."""

from __future__ import annotations

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase


class ClickjackingPlugin(PluginBase):
    name = "clickjacking"
    description = "Check for missing clickjacking protection (X-Frame-Options and/or CSP frame-ancestors)"
    category = "blackbox"
    phase = 2
    base_severity = Severity.MEDIUM
    detection_criteria = "Both X-Frame-Options and CSP frame-ancestors directive are absent"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            try:
                resp = await client.get(target.url)
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

        headers = {k.lower(): v for k, v in resp.headers.items()}

        # Check X-Frame-Options
        xfo = headers.get("x-frame-options", "").strip()
        if xfo:
            return []

        # Check CSP frame-ancestors
        csp = headers.get("content-security-policy", "")
        if "frame-ancestors" in csp.lower():
            return []

        return [Result(
            plugin_name=self.name,
            base_severity=self.base_severity,
            title="Clickjacking: no frame embedding protection",
            description=(
                "The response lacks both an X-Frame-Options header and a CSP frame-ancestors directive. "
                "An attacker can embed this page in an iframe to perform clickjacking attacks."
            ),
            recommendation=(
                "Add 'X-Frame-Options: DENY' (or SAMEORIGIN) and/or a CSP directive "
                "'frame-ancestors 'none'' to prevent iframe embedding."
            ),
            cwe_id="CWE-1021",
            endpoint=target.url,
            rule_id="clickjacking_no_protection",
        )]
