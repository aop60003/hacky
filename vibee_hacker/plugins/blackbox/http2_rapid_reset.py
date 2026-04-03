# vibee_hacker/plugins/blackbox/http2_rapid_reset.py
"""HTTP/2 Rapid Reset DoS risk detection plugin (CVE-2023-44487)."""

from __future__ import annotations

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase


class Http2RapidResetPlugin(PluginBase):
    name = "http2_rapid_reset"
    description = (
        "HTTP/2 Rapid Reset risk — detect HTTP/2 support and report potential "
        "CVE-2023-44487 DoS exposure"
    )
    category = "blackbox"
    phase = 2
    base_severity = Severity.MEDIUM
    destructive_level = 0
    detection_criteria = "Server negotiates HTTP/2 and does not advertise mitigation headers"
    expected_evidence = "HTTP/2 protocol confirmed in response; no Rapid Reset mitigation detected"

    def is_applicable(self, target: Target) -> bool:
        return bool(target.url and target.url.startswith("https://"))

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        # httpx supports HTTP/2 when http2=True is set
        async with httpx.AsyncClient(
            verify=target.verify_ssl,
            timeout=10,
            http2=True,
        ) as client:
            try:
                resp = await client.get(target.url)
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

        # Determine HTTP version used
        http_version = getattr(resp, "http_version", None) or ""
        is_http2 = http_version == "HTTP/2" or http_version.startswith("HTTP/2")

        if not is_http2:
            return []

        resp_headers = {k.lower(): v for k, v in resp.headers.items()}

        # Some servers advertise H2 RST stream limits via Retry-After or custom headers;
        # absence of any mitigation is the finding.
        mitigation_headers = [
            "retry-after",
            "x-ratelimit-limit",
            "x-ratelimit-remaining",
        ]
        has_mitigation = any(h in resp_headers for h in mitigation_headers)

        # We report regardless; mitigation hints reduce severity guidance.
        severity = Severity.LOW if has_mitigation else Severity.MEDIUM

        return [Result(
            plugin_name=self.name,
            base_severity=severity,
            title="HTTP/2 supported — potential Rapid Reset DoS risk (CVE-2023-44487)",
            description=(
                "The server negotiates HTTP/2. CVE-2023-44487 (HTTP/2 Rapid Reset) allows "
                "attackers to send a large number of HEADERS+RST_STREAM frames in rapid "
                "succession to exhaust server resources without completing requests. "
                + (
                    "Rate-limiting headers detected — partial mitigation may be present."
                    if has_mitigation
                    else "No rate-limiting or connection-throttling headers were detected."
                )
            ),
            evidence=(
                f"HTTP version: {http_version} | "
                f"Mitigation headers present: {has_mitigation} | "
                f"Status: {resp.status_code}"
            ),
            recommendation=(
                "Upgrade to a patched server version (nginx ≥1.25.3, Apache ≥2.4.58, etc.) "
                "and configure connection/stream limits. Apply rate limiting at the load balancer."
            ),
            cwe_id="CWE-400",
            endpoint=target.url,
            curl_command=f"curl --http2 -I {target.url!r}",
            rule_id="http2_rapid_reset_risk",
        )]
