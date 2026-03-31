# vibee_hacker/plugins/blackbox/whois_asn.py
"""WHOIS/ASN info collection plugin via HTTP header inspection."""

from __future__ import annotations

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase


class WhoisAsnPlugin(PluginBase):
    name = "whois_asn"
    description = "Collect basic target info: Server header, status code, and resolved endpoint"
    category = "blackbox"
    phase = 1
    base_severity = Severity.INFO
    detection_criteria = "Target responds to HTTP request (info always collected on success)"
    expected_evidence = "HTTP response headers and status from target"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            try:
                resp = await client.get(target.url)
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

        server_header = resp.headers.get("server", "")
        x_powered_by = resp.headers.get("x-powered-by", "")
        status_code = resp.status_code

        info_parts = [f"Status: {status_code}"]
        if server_header:
            info_parts.append(f"Server: {server_header}")
        if x_powered_by:
            info_parts.append(f"X-Powered-By: {x_powered_by}")

        description = (
            f"Basic target information collected from {target.url}. "
            + " | ".join(info_parts)
        )

        return [Result(
            plugin_name=self.name,
            base_severity=Severity.INFO,
            title=f"Target info collected: {target.host}",
            description=description,
            evidence=" | ".join(info_parts),
            recommendation=(
                "Review disclosed server/technology information. "
                "Consider suppressing Server and X-Powered-By headers to reduce fingerprinting."
            ),
            endpoint=target.url,
            rule_id="whois_info_collected",
        )]
