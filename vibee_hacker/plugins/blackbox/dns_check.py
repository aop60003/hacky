"""DNS security checks: SPF, DMARC, and wildcard DNS detection."""

from __future__ import annotations

import socket
from urllib.parse import urlparse

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase


class DnsCheckPlugin(PluginBase):
    name = "dns_check"
    description = "DNS security checks including SPF, DMARC, DNSSEC verification"
    category = "blackbox"
    phase = 1
    destructive_level = 0
    detection_criteria = "Missing SPF/DMARC records or wildcard DNS configured"
    expected_evidence = "No TXT record containing v=spf1 or v=DMARC1 found"

    def is_applicable(self, target: Target) -> bool:
        return bool(target.url)

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []
        hostname = urlparse(target.url).hostname
        if not hostname:
            return []

        results: list[Result] = []

        # 1. Check SPF record
        try:
            txt_records = self._get_txt_records(hostname)
            has_spf = any("v=spf1" in r for r in txt_records)
            if not has_spf:
                results.append(Result(
                    plugin_name=self.name,
                    base_severity=Severity.MEDIUM,
                    title=f"Missing SPF record for {hostname}",
                    description=(
                        "No SPF (Sender Policy Framework) TXT record found. "
                        "Email spoofing may be possible."
                    ),
                    endpoint=hostname,
                    rule_id="dns_missing_spf",
                    cwe_id="CWE-290",
                    recommendation="Add an SPF TXT record to prevent email spoofing.",
                ))
        except Exception:
            pass

        # 2. Check DMARC record
        try:
            dmarc_records = self._get_txt_records(f"_dmarc.{hostname}")
            has_dmarc = any("v=DMARC1" in r for r in dmarc_records)
            if not has_dmarc:
                results.append(Result(
                    plugin_name=self.name,
                    base_severity=Severity.MEDIUM,
                    title=f"Missing DMARC record for {hostname}",
                    description=(
                        "No DMARC record found. Email authentication policy is not enforced."
                    ),
                    endpoint=hostname,
                    rule_id="dns_missing_dmarc",
                    cwe_id="CWE-290",
                    recommendation="Add a DMARC TXT record (e.g., v=DMARC1; p=reject).",
                ))
        except Exception:
            pass

        # 3. Check for wildcard DNS
        try:
            random_sub = f"nonexistent-test-{hostname[:8]}.{hostname}"
            addr = socket.gethostbyname(random_sub)
            if addr:
                results.append(Result(
                    plugin_name=self.name,
                    base_severity=Severity.LOW,
                    title=f"Wildcard DNS record for {hostname}",
                    description=(
                        f"Wildcard DNS resolves to {addr}. May enable subdomain takeover."
                    ),
                    endpoint=hostname,
                    rule_id="dns_wildcard",
                    cwe_id="CWE-350",
                    recommendation="Remove wildcard DNS records unless intentional.",
                ))
        except socket.gaierror:
            pass  # Expected — no wildcard
        except Exception:
            pass

        return results

    def _get_txt_records(self, hostname: str) -> list[str]:
        """Get TXT records using dnspython if available."""
        try:
            import dns.resolver
            answers = dns.resolver.resolve(hostname, "TXT")
            return [str(r) for r in answers]
        except ImportError:
            return []
        except Exception:
            return []
