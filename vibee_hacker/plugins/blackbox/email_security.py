# vibee_hacker/plugins/blackbox/email_security.py
"""Email security headers and MTA-STS policy detection plugin."""

from __future__ import annotations

import shlex

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

EMAIL_SECURITY_HEADERS = [
    "authentication-results",
    "dkim-signature",
    "dmarc",
    "x-dmarc",
]

MTA_STS_PATH = "/.well-known/mta-sts.txt"


def _base_url(url: str) -> str:
    from urllib.parse import urlparse
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


class EmailSecurityPlugin(PluginBase):
    name = "email_security"
    description = "Detect missing email security controls (MTA-STS, DKIM/DMARC headers)"
    category = "blackbox"
    phase = 2
    base_severity = Severity.MEDIUM
    detection_criteria = "No MTA-STS policy and no email authentication headers present"
    expected_evidence = "404 on /.well-known/mta-sts.txt and no Authentication-Results/DKIM headers"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        base = _base_url(target.url)
        results: list[Result] = []

        has_email_headers = False
        has_mta_sts = False

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            # Check main page for email authentication headers
            try:
                resp = await client.get(target.url)
                lower_headers = {k.lower(): v for k, v in resp.headers.items()}
                for header in EMAIL_SECURITY_HEADERS:
                    if header in lower_headers:
                        has_email_headers = True
                        break
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

            # Check for MTA-STS policy
            mta_sts_url = base + MTA_STS_PATH
            try:
                sts_resp = await client.get(mta_sts_url)
                if sts_resp.status_code == 200 and "version" in sts_resp.text.lower():
                    has_mta_sts = True
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                pass

        if not has_mta_sts:
            results.append(Result(
                plugin_name=self.name,
                base_severity=self.base_severity,
                title="MTA-STS policy not found",
                description=(
                    f"No MTA-STS policy was found at {base + MTA_STS_PATH}. "
                    f"MTA-STS enforces TLS for email delivery and prevents downgrade attacks."
                ),
                evidence=f"GET {base + MTA_STS_PATH} returned no valid MTA-STS policy",
                recommendation=(
                    "Publish an MTA-STS policy at /.well-known/mta-sts.txt and configure "
                    "the mta-sts DNS TXT record. Set mode to 'enforce' after testing."
                ),
                cwe_id="CWE-290",
                endpoint=base + MTA_STS_PATH,
                curl_command=f"curl -s {shlex.quote(base + MTA_STS_PATH)}",
                rule_id="email_security_mta_sts_missing",
            ))

        if not has_email_headers:
            results.append(Result(
                plugin_name=self.name,
                base_severity=self.base_severity,
                title="Email authentication headers not present",
                description=(
                    f"No email authentication headers (Authentication-Results, DKIM-Signature) "
                    f"were found in the response from {target.url}. "
                    f"This may indicate SPF, DKIM, and DMARC are not configured."
                ),
                evidence=f"No email authentication headers in response from {target.url}",
                recommendation=(
                    "Configure SPF, DKIM, and DMARC DNS records for your domain. "
                    "Use a DMARC policy of 'reject' or 'quarantine' to prevent spoofing."
                ),
                cwe_id="CWE-290",
                endpoint=target.url,
                curl_command=f"curl -sI {shlex.quote(target.url)}",
                rule_id="email_security_headers_missing",
            ))

        return results
