"""HTTP-based port scanner — probes common web ports using httpx."""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

PORTS = [80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9090, 9200, 27017]
PROBE_TIMEOUT = 3.0


class PortScanPlugin(PluginBase):
    name = "port_scan"
    description = "HTTP-based port scanner: probes common web ports for open services"
    category = "blackbox"
    phase = 1
    base_severity = Severity.INFO
    detection_criteria = "HTTP response received on probed port"
    expected_evidence = "HTTP status code and Server header on open port"

    def is_applicable(self, target: Target) -> bool:
        return bool(target.url)

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        parsed = urlparse(target.url)
        host = parsed.hostname
        if not host:
            return []

        results: list[Result] = []

        async with httpx.AsyncClient(verify=False, timeout=PROBE_TIMEOUT) as client:
            for port in PORTS:
                # Use http:// for non-443/8443 ports, https:// for common TLS ports
                scheme = "https" if port in (443, 8443) else "http"
                probe_url = f"{scheme}://{host}:{port}/"

                try:
                    resp = await client.get(probe_url)
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError,
                        httpx.TimeoutException, httpx.HTTPStatusError):
                    continue

                server_header = resp.headers.get("server", "")
                powered_by = resp.headers.get("x-powered-by", "")
                banner = f"Status: {resp.status_code}"
                if server_header:
                    banner += f", Server: {server_header}"
                if powered_by:
                    banner += f", X-Powered-By: {powered_by}"

                results.append(Result(
                    plugin_name=self.name,
                    base_severity=self.base_severity,
                    title=f"Open port {port} on {host}",
                    description=(
                        f"Port {port} responded to HTTP probe at {probe_url}"
                    ),
                    evidence=banner,
                    endpoint=probe_url,
                    recommendation=(
                        "Verify that this service is intentionally exposed. "
                        "Restrict access to non-essential ports via firewall rules."
                    ),
                    rule_id="port_open",
                ))

        return results
