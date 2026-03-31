# vibee_hacker/plugins/blackbox/security_txt_check.py
"""security.txt RFC 9116 compliance check plugin."""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

SECURITY_TXT_PATH = "/.well-known/security.txt"


def _base_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


class SecurityTxtCheckPlugin(PluginBase):
    name = "security_txt_check"
    description = "Check for presence and RFC 9116 compliance of /.well-known/security.txt"
    category = "blackbox"
    phase = 2
    base_severity = Severity.INFO
    detection_criteria = "security.txt is absent or missing required Contact/Expires fields"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        base = _base_url(target.url)
        endpoint = base + SECURITY_TXT_PATH

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            try:
                resp = await client.get(endpoint)
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

        results: list[Result] = []

        if resp.status_code >= 400:
            results.append(Result(
                plugin_name=self.name,
                base_severity=self.base_severity,
                title="security.txt not found",
                description=(
                    "The application does not serve a /.well-known/security.txt file. "
                    "RFC 9116 recommends providing this file to allow security researchers "
                    "to report vulnerabilities through a defined disclosure channel."
                ),
                recommendation=(
                    "Create a security.txt file at /.well-known/security.txt with at least "
                    "Contact and Expires fields per RFC 9116."
                ),
                evidence=f"HTTP {resp.status_code} at {endpoint}",
                endpoint=endpoint,
                rule_id="security_txt_missing",
            ))
            return results

        # File exists — validate required fields
        body = resp.text
        issues: list[str] = []

        if "contact:" not in body.lower():
            issues.append("missing required 'Contact' field")

        if "expires:" not in body.lower():
            issues.append("missing recommended 'Expires' field")

        if issues:
            results.append(Result(
                plugin_name=self.name,
                base_severity=self.base_severity,
                title="security.txt present but incomplete (RFC 9116)",
                description=(
                    f"The security.txt file exists but is missing fields required or recommended by RFC 9116: "
                    f"{', '.join(issues)}."
                ),
                recommendation=(
                    "Ensure security.txt contains at minimum a 'Contact' field and an 'Expires' field."
                ),
                evidence=f"HTTP {resp.status_code} at {endpoint}; issues: {', '.join(issues)}",
                endpoint=endpoint,
                rule_id="security_txt_incomplete",
            ))

        return results
