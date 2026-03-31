# vibee_hacker/plugins/blackbox/websocket_check.py
"""WebSocket origin validation check plugin."""

from __future__ import annotations

import base64
import os
import shlex

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase


def _ws_key() -> str:
    return base64.b64encode(os.urandom(16)).decode()


class WebsocketCheckPlugin(PluginBase):
    name = "websocket_check"
    description = "Detect WebSocket endpoints without proper Origin validation"
    category = "blackbox"
    phase = 3
    base_severity = Severity.HIGH
    detection_criteria = "WebSocket upgrade accepted (101) with arbitrary evil.com Origin header"
    expected_evidence = "HTTP 101 response to WebSocket upgrade request with Origin: evil.com"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            # Phase 1: Check if WebSocket upgrade is supported at all
            try:
                probe_resp = await client.get(
                    target.url,
                    headers={
                        "Upgrade": "websocket",
                        "Connection": "Upgrade",
                        "Sec-WebSocket-Key": _ws_key(),
                        "Sec-WebSocket-Version": "13",
                        "Origin": target.url.rstrip("/"),
                    },
                )
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

            if probe_resp.status_code != 101:
                return []

            # Phase 2: WebSocket is supported — check if evil origin is accepted
            try:
                evil_resp = await client.get(
                    target.url,
                    headers={
                        "Upgrade": "websocket",
                        "Connection": "Upgrade",
                        "Sec-WebSocket-Key": _ws_key(),
                        "Sec-WebSocket-Version": "13",
                        "Origin": "http://evil.com",
                    },
                )
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

            if evil_resp.status_code == 101:
                return [Result(
                    plugin_name=self.name,
                    base_severity=self.base_severity,
                    title="WebSocket endpoint missing origin validation",
                    description=(
                        f"The WebSocket endpoint at {target.url} accepted an upgrade request "
                        f"with Origin: http://evil.com. Without origin validation, cross-site "
                        f"WebSocket hijacking (CSWSH) attacks are possible."
                    ),
                    evidence=(
                        f"URL: {target.url} | "
                        f"Probe 1 (valid origin): {probe_resp.status_code} | "
                        f"Probe 2 (evil.com origin): {evil_resp.status_code}"
                    ),
                    cwe_id="CWE-346",
                    endpoint=target.url,
                    curl_command=(
                        f"curl -v --include {shlex.quote(target.url)} "
                        f"-H 'Upgrade: websocket' "
                        f"-H 'Connection: Upgrade' "
                        f"-H 'Origin: http://evil.com' "
                        f"-H 'Sec-WebSocket-Version: 13' "
                        f"-H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=='"
                    ),
                    rule_id="websocket_no_origin_check",
                )]

        return []
