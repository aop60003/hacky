# vibee_hacker/plugins/blackbox/subdomain_enum.py
"""Subdomain enumeration plugin using HTTP probing."""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

COMMON_SUBDOMAINS = [
    "www", "mail", "api", "dev", "staging", "admin",
    "test", "cdn", "app", "blog",
]


class SubdomainEnumPlugin(PluginBase):
    name = "subdomain_enum"
    description = "HTTP-based subdomain discovery via probing common subdomain names"
    category = "blackbox"
    phase = 1
    base_severity = Severity.INFO
    detection_criteria = "Subdomain responds with HTTP 200, 301, or 302"
    expected_evidence = "HTTP response received from {subdomain}.{host}"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        parsed = urlparse(target.url)
        host = parsed.hostname
        if not host:
            return []

        scheme = parsed.scheme or "http"
        results: list[Result] = []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10, follow_redirects=False) as client:
            for sub in COMMON_SUBDOMAINS:
                subdomain_url = f"{scheme}://{sub}.{host}/"
                try:
                    resp = await client.get(subdomain_url)
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                if resp.status_code in (200, 301, 302):
                    results.append(Result(
                        plugin_name=self.name,
                        base_severity=Severity.INFO,
                        title=f"Subdomain discovered: {sub}.{host}",
                        description=(
                            f"Subdomain {sub}.{host} responded with HTTP {resp.status_code}. "
                            f"Active subdomains expand the attack surface."
                        ),
                        evidence=f"GET {subdomain_url} -> HTTP {resp.status_code}",
                        recommendation=(
                            "Review discovered subdomains for unnecessary exposure. "
                            "Decommission unused subdomains to reduce attack surface."
                        ),
                        endpoint=subdomain_url,
                        rule_id="subdomain_discovered",
                    ))

        return results
