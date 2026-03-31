# vibee_hacker/plugins/blackbox/dns_zone_transfer.py
"""DNS zone transfer / DNS admin interface exposure detection plugin."""

from __future__ import annotations

import re
import shlex
from urllib.parse import urlparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

# Common DNS admin/info endpoints
DNS_ADMIN_PATHS = [
    "/dns",
    "/bind",
    "/named",
    "/dns-query",
    "/dns-admin",
    "/zone",
    "/nameserver",
]

# Patterns indicative of DNS zone data exposure
DNS_INFO_PATTERNS = [
    re.compile(r"\bNS\s+record\b", re.I),
    re.compile(r"\bSOA\b.{0,60}\b(?:ns\d*|nameserver)\b", re.I),
    re.compile(r"\bIN\s+(?:A|AAAA|CNAME|MX|NS|SOA|TXT)\b"),
    re.compile(r"\baxfr\b", re.I),
    re.compile(r"\bzone\s+transfer\b", re.I),
    re.compile(r"\bnamed\.conf\b", re.I),
    re.compile(r"\brndc\b", re.I),
]


def _base_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


class DnsZoneTransferPlugin(PluginBase):
    name = "dns_zone_transfer"
    description = "Detect DNS zone information exposure via HTTP admin interfaces"
    category = "blackbox"
    phase = 1
    base_severity = Severity.HIGH
    detection_criteria = "DNS NS/SOA/zone transfer data accessible via HTTP endpoint"
    expected_evidence = "DNS record patterns (NS, SOA, AXFR, zone transfer) found in HTTP response"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        base = _base_url(target.url)
        results: list[Result] = []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            for path in DNS_ADMIN_PATHS:
                endpoint = base + path
                try:
                    resp = await client.get(endpoint)
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                if resp.status_code not in (200, 206):
                    continue

                body = resp.text[:500_000]
                for pattern in DNS_INFO_PATTERNS:
                    if pattern.search(body):
                        results.append(Result(
                            plugin_name=self.name,
                            base_severity=self.base_severity,
                            title="DNS zone information exposed via HTTP",
                            description=(
                                f"The endpoint {endpoint} returns DNS zone information "
                                f"including NS/SOA records or zone transfer data. "
                                f"Attackers can enumerate the entire DNS zone to map the network."
                            ),
                            evidence=(
                                f"Path: {path} | Status: {resp.status_code} | "
                                f"Pattern matched: {pattern.pattern}"
                            ),
                            cwe_id="CWE-200",
                            endpoint=endpoint,
                            curl_command=f"curl -v {shlex.quote(endpoint)}",
                            rule_id="dns_zone_info_exposed",
                        ))
                        return results  # Stop on first finding

        return results
