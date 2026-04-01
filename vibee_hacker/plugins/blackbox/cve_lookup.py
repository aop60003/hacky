"""CVE Lookup plugin — checks detected service versions against built-in CVE database."""

from __future__ import annotations

import re

import httpx

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

# Built-in CVE database: maps version string fragment → CVE metadata
# Format: (match_pattern, cve_id, severity, cwe_id, description)
CVE_DB: list[tuple[re.Pattern, str, Severity, str, str]] = [
    (
        re.compile(r"Apache/2\.4\.49\b"),
        "CVE-2021-41773",
        Severity.CRITICAL,
        "CWE-22",
        "Apache HTTP Server 2.4.49 path traversal and RCE (mod_cgi)",
    ),
    (
        re.compile(r"Apache/2\.4\.50\b"),
        "CVE-2021-42013",
        Severity.CRITICAL,
        "CWE-22",
        "Apache HTTP Server 2.4.50 path traversal bypass",
    ),
    (
        re.compile(r"[Nn]ginx/1\.16\b"),
        "CVE-2019-20372",
        Severity.HIGH,
        "CWE-444",
        "Nginx 1.16 HTTP request smuggling via malformed header",
    ),
    (
        re.compile(r"PHP/7\.4\b"),
        "CVE-2022-31628",
        Severity.MEDIUM,
        "CWE-400",
        "PHP 7.4 DoS via phar:// wrapper infinite recursion",
    ),
    (
        re.compile(r"OpenSSL/1\.0\b"),
        "CVE-2014-0160",
        Severity.CRITICAL,
        "CWE-125",
        "Heartbleed: OpenSSL 1.0.1 memory disclosure via TLS heartbeat",
    ),
    (
        re.compile(r"jQuery/1\.\d+|jquery-1\.\d+"),
        "CVE-2020-11022",
        Severity.MEDIUM,
        "CWE-79",
        "jQuery 1.x XSS via untrusted HTML passed to DOM manipulation methods",
    ),
]


def _collect_version_strings(context: InterPhaseContext | None, server_header: str) -> list[str]:
    """Gather all version strings to check: tech_stack + Server header."""
    candidates: list[str] = []
    if server_header:
        candidates.append(server_header)
    if context and context.tech_stack:
        candidates.extend(context.tech_stack)
    return candidates


class CveLookupPlugin(PluginBase):
    name = "cve_lookup"
    description = "Check detected service versions against built-in known CVE database"
    category = "blackbox"
    phase = 1
    base_severity = Severity.MEDIUM
    requires = ["tech_stack"]
    detection_criteria = "Detected version string matches a known CVE entry"
    expected_evidence = "CVE ID, affected version string, and severity"

    def is_applicable(self, target: Target) -> bool:
        return bool(target.url)

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        # Fetch live headers to get Server version info
        server_header = ""
        try:
            async with httpx.AsyncClient(
                verify=target.verify_ssl,
                timeout=10,
                follow_redirects=True,
            ) as client:
                resp = await client.get(target.url)
                server_header = resp.headers.get("server", "")
        except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError,
                httpx.TimeoutException):
            pass

        candidates = _collect_version_strings(context, server_header)
        if not candidates:
            return []

        results: list[Result] = []
        seen_cves: set[str] = set()

        for candidate in candidates:
            for pattern, cve_id, severity, cwe_id, description in CVE_DB:
                if cve_id in seen_cves:
                    continue
                if pattern.search(candidate):
                    seen_cves.add(cve_id)
                    results.append(Result(
                        plugin_name=self.name,
                        base_severity=severity,
                        title=f"{cve_id}: {description}",
                        description=(
                            f"Detected version '{candidate}' matches known vulnerability "
                            f"{cve_id}. {description}"
                        ),
                        evidence=f"Version string: {candidate}",
                        endpoint=target.url,
                        cwe_id=cwe_id,
                        recommendation=(
                            f"Update the affected component immediately. "
                            f"See https://nvd.nist.gov/vuln/detail/{cve_id} for details."
                        ),
                        rule_id="cve_known",
                    ))

        return results
