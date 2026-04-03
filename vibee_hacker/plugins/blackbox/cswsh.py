"""Plugin: Cross-Site WebSocket Hijacking (CSWSH) Detection (blackbox)."""
from __future__ import annotations

from urllib.parse import urlparse, urlunparse

import httpx

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

EVIL_ORIGINS = [
    "https://attacker.example.com",
    "https://evil.com",
    "null",
]

WS_PATHS = [
    "/ws",
    "/websocket",
    "/socket",
    "/chat",
    "/api/ws",
    "/live",
]


class CswshPlugin(PluginBase):
    name = "cswsh"
    description = "Detect Cross-Site WebSocket Hijacking by connecting with evil Origin headers"
    category = "blackbox"
    phase = 3
    base_severity = Severity.HIGH

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        parsed = urlparse(target.url)
        base = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
        results: list[Result] = []

        # Build list of WebSocket endpoints to test
        ws_endpoints: list[str] = []
        for path in WS_PATHS:
            ws_endpoints.append(base + path)
        if context and context.crawl_urls:
            for u in context.crawl_urls:
                if any(kw in u.lower() for kw in ["ws", "socket", "chat", "live"]):
                    if u not in ws_endpoints:
                        ws_endpoints.append(u)

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            for endpoint in ws_endpoints[:6]:
                # We probe using HTTP (GET with Upgrade: websocket headers)
                # A proper WS client is complex; we check if the server responds to
                # the WS handshake with a 101 when evil Origin is sent

                for evil_origin in EVIL_ORIGINS:
                    ws_headers = {
                        "Upgrade": "websocket",
                        "Connection": "Upgrade",
                        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                        "Sec-WebSocket-Version": "13",
                        "Origin": evil_origin,
                    }
                    try:
                        resp = await client.get(endpoint, headers=ws_headers)
                    except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                        continue

                    # 101 Switching Protocols = WebSocket accepted without Origin validation
                    if resp.status_code == 101:
                        results.append(
                            Result(
                                plugin_name=self.name,
                                base_severity=Severity.HIGH,
                                title="Cross-Site WebSocket Hijacking (CSWSH)",
                                description=(
                                    f"WebSocket endpoint at {endpoint} accepted connection from evil Origin "
                                    f"'{evil_origin}' (HTTP 101 Switching Protocols). "
                                    "An attacker can create a malicious page that connects to this WebSocket "
                                    "and sends authenticated messages on behalf of the victim."
                                ),
                                evidence=f"GET {endpoint} with Origin: {evil_origin} → {resp.status_code}",
                                recommendation=(
                                    "Validate the Origin header in WebSocket handshake and reject connections "
                                    "from untrusted origins. Implement CSRF tokens for WebSocket authentication."
                                ),
                                cwe_id="CWE-346",
                                rule_id="cswsh",
                                endpoint=endpoint,
                            )
                        )
                        return results

                    # Also check if the endpoint exists but may have CSWSH risk (200 with WS content)
                    if resp.status_code == 200:
                        body_lower = resp.text[:2000].lower()
                        if any(kw in body_lower for kw in ["websocket", "upgrade", "socket"]):
                            # Endpoint seems WS-related but didn't upgrade; might need JS to initiate
                            pass

        return results
