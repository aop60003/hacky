# vibee_hacker/plugins/blackbox/snmp_check.py
"""SNMP management interface exposure detection plugin."""

from __future__ import annotations

import re
import shlex
from urllib.parse import urlparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

# Common SNMP / network monitoring management paths
SNMP_PATHS = [
    "/snmp",
    "/mrtg",
    "/cacti",
    "/nagios",
    "/monitoring",
    "/netflow",
    "/nms",
    "/snmpwalk",
]

# Patterns indicating SNMP-related content
SNMP_PATTERNS = [
    re.compile(r"\bsnmp\b", re.I),
    re.compile(r"\bcommunity\s*(?:string)?\s*:", re.I),
    re.compile(r"\bOID\s*:\s*\d+\.\d+\.\d+", re.I),
    re.compile(r"\bpublic\b.{0,30}\bsnmp\b", re.I),
    re.compile(r"\bprivate\b.{0,30}\bsnmp\b", re.I),
    re.compile(r"1\.3\.6\.1\.2\.1\.\d+", re.I),  # Standard MIB OID prefix
    re.compile(r"\bmrtg\b", re.I),
    re.compile(r"\bnagios\b", re.I),
    re.compile(r"\bcacti\b", re.I),
]


def _base_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


class SnmpCheckPlugin(PluginBase):
    name = "snmp_check"
    description = "Detect SNMP management interfaces and community string exposure via HTTP"
    category = "blackbox"
    phase = 1
    base_severity = Severity.HIGH
    detection_criteria = "SNMP management interface accessible via HTTP with community string or OID data"
    expected_evidence = "SNMP community string, OID pattern, or management interface in HTTP response"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        base = _base_url(target.url)
        results: list[Result] = []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            for path in SNMP_PATHS:
                endpoint = base + path
                try:
                    resp = await client.get(endpoint)
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                if resp.status_code not in (200, 206):
                    continue

                body = resp.text[:500_000]
                for pattern in SNMP_PATTERNS:
                    if pattern.search(body):
                        results.append(Result(
                            plugin_name=self.name,
                            base_severity=self.base_severity,
                            title="SNMP management interface exposed via HTTP",
                            description=(
                                f"The endpoint {endpoint} is accessible and contains SNMP-related "
                                f"information. Exposed SNMP community strings or management "
                                f"interfaces allow attackers to enumerate network devices and "
                                f"potentially modify device configuration."
                            ),
                            evidence=(
                                f"Path: {path} | Status: {resp.status_code} | "
                                f"Pattern matched: {pattern.pattern}"
                            ),
                            cwe_id="CWE-200",
                            endpoint=endpoint,
                            curl_command=f"curl -v {shlex.quote(endpoint)}",
                            rule_id="snmp_interface_exposed",
                        ))
                        return results  # Stop on first finding

        return results
