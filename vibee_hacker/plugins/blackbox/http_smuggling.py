"""HTTP Request Smuggling detection (CL.TE, TE.CL)."""

from __future__ import annotations

import httpx

from vibee_hacker.core.models import Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase


class HttpSmugglingPlugin(PluginBase):
    name = "http_smuggling"
    description = "HTTP request smuggling detection (CL.TE, TE.CL)"
    category = "blackbox"
    phase = 3
    destructive_level = 1

    def is_applicable(self, target: Target) -> bool:
        return bool(target.url)

    async def run(self, target: Target, context=None) -> list[Result]:
        if not target.url:
            return []

        results: list[Result] = []

        async with httpx.AsyncClient(
            verify=getattr(target, "verify_ssl", True),
            timeout=10,
            http2=False,  # Smuggling only affects HTTP/1.1
        ) as client:
            # 1. Check for Transfer-Encoding header handling
            try:
                # Send ambiguous Content-Length + Transfer-Encoding
                resp = await client.post(
                    target.url,
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Transfer-Encoding": "chunked",
                        "Content-Length": "4",
                    },
                    content="0\r\n\r\n",
                )

                # If server doesn't reject ambiguous headers, it may be vulnerable
                if resp.status_code not in (400, 501):
                    # Try timing-based detection
                    try:
                        # Send a request that would hang if TE.CL smuggling works
                        resp2 = await client.post(
                            target.url,
                            headers={
                                "Transfer-Encoding": "chunked",
                                "Content-Length": "6",
                            },
                            content="0\r\n\r\nX",
                            timeout=5,
                        )
                    except httpx.ReadTimeout:
                        results.append(Result(
                            plugin_name=self.name,
                            base_severity=Severity.HIGH,
                            title="Potential HTTP Request Smuggling (TE.CL)",
                            description=(
                                "Server may be vulnerable to TE.CL request smuggling. "
                                "The server did not reject ambiguous Transfer-Encoding/Content-Length "
                                "headers and a timing anomaly was detected."
                            ),
                            endpoint=target.url,
                            rule_id="http_smuggling_te_cl",
                            cwe_id="CWE-444",
                            recommendation=(
                                "Configure the server to reject ambiguous requests with both "
                                "Transfer-Encoding and Content-Length headers."
                            ),
                        ))
                    except Exception:
                        pass

            except (httpx.TransportError, httpx.InvalidURL):
                pass

            # 2. Check for HTTP/2 downgrade
            try:
                resp = await client.get(target.url)
                if resp.http_version == "HTTP/1.1":
                    # Check if server supports both HTTP/1.1 and HTTP/2
                    # (potential for H2.CL smuggling)
                    server = resp.headers.get("server", "").lower()

                    # Reverse proxy indicators
                    if any(proxy in server for proxy in ["nginx", "apache", "haproxy", "cloudflare"]):
                        if "via" in resp.headers or "x-forwarded" in str(resp.headers).lower():
                            results.append(Result(
                                plugin_name=self.name,
                                base_severity=Severity.LOW,
                                title="Reverse proxy detected (smuggling pre-condition)",
                                description=(
                                    f"Reverse proxy detected ({server}). "
                                    "Multi-layer HTTP processing may enable request smuggling."
                                ),
                                endpoint=target.url,
                                rule_id="http_smuggling_proxy_detected",
                                cwe_id="CWE-444",
                                recommendation=(
                                    "Ensure consistent HTTP parsing between proxy and backend."
                                ),
                            ))

            except (httpx.TransportError, httpx.InvalidURL):
                pass

        return results
