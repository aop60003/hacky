"""WebSocket security scanner."""

from __future__ import annotations

import re

import httpx

from vibee_hacker.core.models import Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

WS_PATHS = ["/ws", "/websocket", "/socket.io/", "/sockjs/", "/cable", "/hub", "/signalr"]


class WebsocketCheckPlugin(PluginBase):
    name = "websocket_check"
    description = "WebSocket endpoint discovery and security checks"
    category = "blackbox"
    phase = 2
    destructive_level = 0

    def is_applicable(self, target: Target) -> bool:
        return bool(target.url)

    async def run(self, target: Target, context=None) -> list[Result]:
        if not target.url:
            return []

        results: list[Result] = []
        base_url = target.url.rstrip("/")

        async with httpx.AsyncClient(
            verify=getattr(target, "verify_ssl", True),
            timeout=10,
            follow_redirects=True,
        ) as client:
            # 1. Check main page for WebSocket references
            try:
                resp = await client.get(base_url)
                page_content = resp.text

                # Find ws:// or wss:// URLs in page
                ws_urls = re.findall(r'wss?://[^\s"\'<>]+', page_content)

                # Find WebSocket constructor usage
                ws_constructors = re.findall(
                    r'new\s+WebSocket\s*\(\s*["\']([^"\']+)', page_content
                )
                ws_urls.extend(ws_constructors)

                # Find socket.io references
                if "socket.io" in page_content.lower():
                    results.append(Result(
                        plugin_name=self.name,
                        base_severity=Severity.INFO,
                        title="Socket.IO detected",
                        description="Socket.IO library found in page source.",
                        endpoint=base_url,
                        rule_id="ws_socketio_detected",
                        recommendation="Ensure Socket.IO is configured with authentication.",
                    ))

                # Report discovered WS endpoints
                for ws_url in set(ws_urls):
                    results.append(Result(
                        plugin_name=self.name,
                        base_severity=Severity.INFO,
                        title=f"WebSocket endpoint: {ws_url[:80]}",
                        description="WebSocket endpoint discovered in page source.",
                        endpoint=ws_url,
                        rule_id="ws_endpoint_found",
                    ))

                    # Check if WS uses unencrypted protocol (CSWSH pre-condition)
                    if ws_url.startswith("ws://"):
                        results.append(Result(
                            plugin_name=self.name,
                            base_severity=Severity.MEDIUM,
                            title="Unencrypted WebSocket (ws://)",
                            description=f"WebSocket uses unencrypted ws:// protocol: {ws_url[:80]}",
                            endpoint=ws_url,
                            rule_id="ws_unencrypted",
                            cwe_id="CWE-319",
                            recommendation="Use wss:// (encrypted) WebSocket connections.",
                        ))

            except (httpx.TransportError, httpx.InvalidURL):
                pass

            # 2. Probe common WS upgrade paths
            for path in WS_PATHS:
                probe_url = f"{base_url}{path}"
                try:
                    resp = await client.get(
                        probe_url,
                        headers={
                            "Upgrade": "websocket",
                            "Connection": "Upgrade",
                            "Sec-WebSocket-Version": "13",
                            "Sec-WebSocket-Key": "dGVzdA==",
                        },
                    )
                    # 101 Switching Protocols = WS endpoint found
                    if resp.status_code == 101:
                        results.append(Result(
                            plugin_name=self.name,
                            base_severity=Severity.MEDIUM,
                            title=f"WebSocket endpoint accepts upgrade at {path}",
                            description=(
                                "Server accepted WebSocket upgrade without apparent authentication."
                            ),
                            endpoint=probe_url,
                            rule_id="ws_unauthenticated_upgrade",
                            cwe_id="CWE-306",
                            recommendation="Add authentication to WebSocket endpoints.",
                        ))
                    elif resp.status_code == 400 and "upgrade" in resp.text.lower():
                        results.append(Result(
                            plugin_name=self.name,
                            base_severity=Severity.INFO,
                            title=f"Possible WebSocket endpoint at {path}",
                            description=(
                                "Server responded to upgrade attempt (400 with upgrade mention)."
                            ),
                            endpoint=probe_url,
                            rule_id="ws_possible_endpoint",
                        ))
                except (httpx.TransportError, httpx.InvalidURL):
                    continue

        return results[:15]
