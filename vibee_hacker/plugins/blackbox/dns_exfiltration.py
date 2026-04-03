"""Plugin: DNS Exfiltration Risk Detection (blackbox)."""
from __future__ import annotations

import re

import httpx

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

# Base64-like subdomain pattern: long encoded subdomains typical of DNS exfiltration
BASE64_SUBDOMAIN_RE = re.compile(
    r'([A-Za-z0-9+/=]{20,})\.[a-z]{2,}',
    re.IGNORECASE,
)

# Hex-encoded subdomains (common in DNS exfil tools)
HEX_SUBDOMAIN_RE = re.compile(
    r'\b([0-9a-f]{32,})\.[a-z]{2,}\b',
    re.IGNORECASE,
)

# Suspicious TXT record patterns
DNS_EXFIL_TXT_RE = re.compile(
    r'(data:|base64:|exfil|dnstunnel|iodine|dnscat|dns2tcp)',
    re.IGNORECASE,
)

# Patterns indicating DNS-based data channels in responses
DNS_CHANNEL_INDICATORS = [
    re.compile(r'dns.*tunnel', re.IGNORECASE),
    re.compile(r'dns.*exfil', re.IGNORECASE),
    re.compile(r'iodine', re.IGNORECASE),
    re.compile(r'dnscat', re.IGNORECASE),
    re.compile(r'dns2tcp', re.IGNORECASE),
]

PROBE_PATHS = [
    "/",
    "/api/",
    "/status",
    "/health",
    "/debug",
    "/admin",
]


class DnsExfiltrationPlugin(PluginBase):
    name = "dns_exfiltration"
    description = "Detect DNS exfiltration indicators in HTTP responses (base64 subdomains, DNS tunnel patterns)"
    category = "blackbox"
    phase = 3
    base_severity = Severity.MEDIUM

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        results: list[Result] = []
        urls_to_probe: list[str] = [target.url]

        if context and context.crawl_urls:
            for u in context.crawl_urls[:5]:
                if u not in urls_to_probe:
                    urls_to_probe.append(u)

        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(target.url)
        base = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
        for path in PROBE_PATHS:
            u = base + path
            if u not in urls_to_probe:
                urls_to_probe.append(u)

        seen_endpoints: set[str] = set()

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            for url in urls_to_probe[:8]:
                try:
                    resp = await client.get(url)
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                body = resp.text[:10000]

                # Check for DNS exfiltration tool references
                for pattern in DNS_CHANNEL_INDICATORS:
                    m = pattern.search(body)
                    if m and url not in seen_endpoints:
                        seen_endpoints.add(url)
                        results.append(
                            Result(
                                plugin_name=self.name,
                                base_severity=Severity.MEDIUM,
                                title="DNS Exfiltration Tool Reference Detected",
                                description=(
                                    f"Response from {url} contains a reference to a DNS exfiltration tool "
                                    f"('{m.group()}'), suggesting the server may be involved in DNS tunneling."
                                ),
                                evidence=f"GET {url} → matched pattern: {m.group()} in response body",
                                recommendation=(
                                    "Investigate whether this server is running DNS tunneling software. "
                                    "Monitor outbound DNS traffic for abnormal query patterns."
                                ),
                                cwe_id="CWE-200",
                                rule_id="dns_exfiltration_risk",
                                endpoint=url,
                            )
                        )
                        break

                # Check for base64-encoded subdomain patterns in response
                for m in BASE64_SUBDOMAIN_RE.finditer(body):
                    candidate = m.group(1)
                    if len(candidate) >= 24 and url not in seen_endpoints:
                        seen_endpoints.add(url)
                        results.append(
                            Result(
                                plugin_name=self.name,
                                base_severity=Severity.LOW,
                                title="Base64-Encoded Subdomain Pattern Detected",
                                description=(
                                    f"Response from {url} contains what appears to be a base64-encoded "
                                    f"subdomain ('{candidate[:40]}...'), a common DNS exfiltration indicator."
                                ),
                                evidence=f"GET {url} → suspicious subdomain pattern: {m.group()[:80]}",
                                recommendation=(
                                    "Audit DNS query logs for high-entropy subdomain patterns. "
                                    "Deploy DNS monitoring to detect data exfiltration via DNS."
                                ),
                                cwe_id="CWE-200",
                                rule_id="dns_exfiltration_risk",
                                endpoint=url,
                            )
                        )
                        break

        return results
