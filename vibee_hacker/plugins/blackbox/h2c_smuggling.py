"""Plugin: HTTP/2 Cleartext (h2c) Upgrade Smuggling Detection (blackbox)."""
from __future__ import annotations

import httpx

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

H2C_HEADERS = {
    "Upgrade": "h2c",
    "HTTP2-Settings": "AAMAAABkAAQAAP__",
    "Connection": "Upgrade, HTTP2-Settings",
}


class H2cSmugglingPlugin(PluginBase):
    name = "h2c_smuggling"
    description = "Check for HTTP/2 cleartext (h2c) upgrade acceptance that may allow request smuggling"
    category = "blackbox"
    phase = 3
    base_severity = Severity.HIGH

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        results: list[Result] = []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10, http2=False) as client:
            # Test 1: Send h2c Upgrade request
            try:
                resp = await client.get(target.url, headers=H2C_HEADERS)
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

            status = resp.status_code
            upgrade_header = resp.headers.get("upgrade", "").lower()
            connection_header = resp.headers.get("connection", "").lower()

            # 101 Switching Protocols = server accepted h2c upgrade
            if status == 101:
                results.append(
                    Result(
                        plugin_name=self.name,
                        base_severity=Severity.HIGH,
                        title="h2c Upgrade Accepted (HTTP/2 Cleartext Smuggling Risk)",
                        description=(
                            f"The server at {target.url} returned HTTP 101 in response to an h2c Upgrade request. "
                            "This may allow request smuggling through proxies that forward h2c upgrades without "
                            "proper validation."
                        ),
                        evidence=f"GET {target.url} with Upgrade: h2c → {status} {resp.headers.get('upgrade', '')}",
                        recommendation=(
                            "Disable h2c upgrade support on front-end proxies, or ensure proxies strip "
                            "Upgrade: h2c headers from client requests. Use HTTP/2 over TLS (h2) instead."
                        ),
                        cwe_id="CWE-444",
                        rule_id="h2c_smuggling",
                        endpoint=target.url,
                    )
                )
                return results

            # Test 2: Check if server echoes back h2c upgrade headers (misconfigured proxy)
            if "h2c" in upgrade_header or "h2c" in connection_header:
                results.append(
                    Result(
                        plugin_name=self.name,
                        base_severity=Severity.MEDIUM,
                        title="Server Reflects h2c Upgrade Headers",
                        description=(
                            f"The server at {target.url} reflects h2c-related headers in its response, "
                            "indicating potential h2c upgrade handling that could be exploited."
                        ),
                        evidence=f"Response headers: Upgrade={resp.headers.get('upgrade', '')}, Connection={resp.headers.get('connection', '')}",
                        recommendation=(
                            "Configure the server/proxy to reject or strip h2c Upgrade headers from client requests."
                        ),
                        cwe_id="CWE-444",
                        rule_id="h2c_smuggling",
                        endpoint=target.url,
                    )
                )

        return results
