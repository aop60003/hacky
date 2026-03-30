# vibee_hacker/plugins/blackbox/unnecessary_services.py
"""Unnecessary services exposure detection plugin."""

from __future__ import annotations

import shlex
from urllib.parse import urlparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

# (path, severity) tuples - /actuator/env is CRITICAL due to secret exposure
SERVICE_PATHS: list[tuple[str, Severity]] = [
    ("/actuator", Severity.MEDIUM),
    ("/actuator/env", Severity.CRITICAL),
    ("/metrics", Severity.MEDIUM),
    ("/health", Severity.MEDIUM),
    ("/phpinfo.php", Severity.HIGH),
    ("/server-status", Severity.MEDIUM),
    ("/elmah.axd", Severity.HIGH),
    ("/.env", Severity.CRITICAL),
    ("/wp-admin", Severity.MEDIUM),
]

MIN_CONTENT_LENGTH = 50


def _base_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


class UnnecessaryServicesPlugin(PluginBase):
    name = "unnecessary_services"
    description = "Detect exposed unnecessary services (actuator, metrics, phpinfo, etc.)"
    category = "blackbox"
    phase = 2
    base_severity = Severity.MEDIUM
    detection_criteria = "Service endpoint returns 200 with content length > 50 chars"
    expected_evidence = "Accessible management or diagnostic endpoint with content"
    detection_criteria = "Management/diagnostic endpoint accessible with meaningful content"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        base = _base_url(target.url)
        results: list[Result] = []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            for path, severity in SERVICE_PATHS:
                endpoint = base + path
                try:
                    resp = await client.get(endpoint)
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                if resp.status_code != 200:
                    continue

                if len(resp.text) <= MIN_CONTENT_LENGTH:
                    continue

                if len(resp.text) > 1_000_000:
                    continue

                results.append(Result(
                    plugin_name=self.name,
                    base_severity=severity,
                    title=f"Unnecessary service exposed: {path}",
                    description=(
                        f"A management or diagnostic endpoint is publicly accessible at {endpoint}. "
                        f"This may expose sensitive configuration, environment variables, or system information."
                    ),
                    evidence=f"Path: {path} | Status: {resp.status_code} | Content length: {len(resp.text)}",
                    cwe_id="CWE-16",
                    endpoint=endpoint,
                    curl_command=f"curl {shlex.quote(endpoint)}",
                    rule_id="unnecessary_service_exposed",
                ))
                return results  # Stop on first finding

        return results
