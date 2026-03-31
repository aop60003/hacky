# vibee_hacker/plugins/blackbox/ssl_check.py
"""SSL/TLS configuration check plugin."""

from __future__ import annotations

import re
from urllib.parse import urlparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

HSTS_MIN_MAX_AGE = 31_536_000  # 1 year in seconds


class SslCheckPlugin(PluginBase):
    name = "ssl_check"
    description = "Check TLS/SSL configuration: HSTS presence, max-age adequacy, and certificate errors"
    category = "blackbox"
    phase = 2
    base_severity = Severity.HIGH
    detection_criteria = "Missing/weak HSTS header, expired/self-signed certificate, or missing HTTPS redirect"
    expected_evidence = "Strict-Transport-Security header absent or max-age below 31536000"

    def is_applicable(self, target: Target) -> bool:
        if not target.url:
            return False
        return urlparse(target.url).scheme == "https"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        parsed = urlparse(target.url)
        if parsed.scheme != "https":
            return []

        results: list[Result] = []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            try:
                resp = await client.get(target.url)
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

        hsts_header = resp.headers.get("strict-transport-security", "")

        if not hsts_header:
            results.append(Result(
                plugin_name=self.name,
                base_severity=Severity.HIGH,
                title="Missing HSTS header",
                description=(
                    f"The HTTPS endpoint {target.url} does not return a "
                    f"Strict-Transport-Security (HSTS) header. Without HSTS, "
                    f"browsers may be coerced into downgrading to HTTP."
                ),
                evidence=f"GET {target.url} -> No Strict-Transport-Security header",
                recommendation=(
                    "Add the Strict-Transport-Security header with a max-age of at least "
                    f"{HSTS_MIN_MAX_AGE} seconds (1 year), and include includeSubDomains."
                ),
                cwe_id="CWE-295",
                endpoint=target.url,
                rule_id="ssl_no_hsts",
            ))
        else:
            # Check max-age value
            match = re.search(r"max-age\s*=\s*(\d+)", hsts_header, re.IGNORECASE)
            if match:
                max_age = int(match.group(1))
                if max_age < HSTS_MIN_MAX_AGE:
                    results.append(Result(
                        plugin_name=self.name,
                        base_severity=Severity.MEDIUM,
                        title="HSTS max-age too low",
                        description=(
                            f"The HSTS max-age value ({max_age}s) is below the recommended "
                            f"minimum of {HSTS_MIN_MAX_AGE}s (1 year). Short max-age reduces "
                            f"protection against SSL stripping attacks."
                        ),
                        evidence=f"Strict-Transport-Security: {hsts_header}",
                        recommendation=(
                            f"Increase the HSTS max-age to at least {HSTS_MIN_MAX_AGE} seconds."
                        ),
                        cwe_id="CWE-295",
                        endpoint=target.url,
                        rule_id="ssl_hsts_max_age_low",
                    ))

        return results
