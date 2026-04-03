"""Plugin: Server-Side Prototype Pollution Detection (blackbox)."""
from __future__ import annotations

import json

import httpx

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

PAYLOADS = [
    {"__proto__": {"polluted": "vibee_pp_test"}},
    {"constructor": {"prototype": {"polluted": "vibee_pp_test"}}},
    {"__proto__[polluted]": "vibee_pp_test"},
]

ENDPOINTS = ["/api/", "/api/v1/", "/api/v2/", "/graphql", "/"]


class ServerProtoPollutionPlugin(PluginBase):
    name = "server_proto_pollution"
    description = "Detect server-side prototype pollution via JSON __proto__ key injection"
    category = "blackbox"
    phase = 3
    base_severity = Severity.HIGH

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        results: list[Result] = []

        endpoints_to_test: list[str] = [target.url]
        if context and context.crawl_urls:
            for u in context.crawl_urls[:5]:
                if u not in endpoints_to_test:
                    endpoints_to_test.append(u)

        # Add common API paths derived from target url base
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(target.url)
        base = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
        for ep in ENDPOINTS:
            candidate = base + ep
            if candidate not in endpoints_to_test:
                endpoints_to_test.append(candidate)

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            for endpoint in endpoints_to_test[:8]:
                for payload in PAYLOADS:
                    try:
                        resp = await client.post(
                            endpoint,
                            content=json.dumps(payload),
                            headers={"Content-Type": "application/json"},
                        )
                    except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                        continue

                    # Indicators: 500 error with prototype-related message, or reflected polluted key
                    body = resp.text[:5000]
                    is_500 = resp.status_code == 500
                    has_proto_error = any(
                        kw in body.lower()
                        for kw in ("__proto__", "prototype", "cannot set property", "polluted")
                    )
                    has_reflection = "vibee_pp_test" in body

                    if has_reflection or (is_500 and has_proto_error):
                        reason = "payload reflected in response" if has_reflection else "500 error with prototype-related message"
                        results.append(
                            Result(
                                plugin_name=self.name,
                                base_severity=Severity.HIGH,
                                title="Server-Side Prototype Pollution",
                                description=(
                                    f"Server processed a __proto__ JSON key injection payload at {endpoint}. "
                                    f"Evidence: {reason}."
                                ),
                                evidence=f"POST {endpoint} with {json.dumps(payload)[:80]} → {resp.status_code}: {body[:200]}",
                                recommendation=(
                                    "Sanitize JSON input server-side to remove __proto__, constructor, and prototype keys. "
                                    "Use Object.create(null) for untrusted data parsing."
                                ),
                                cwe_id="CWE-1321",
                                rule_id="server_prototype_pollution",
                                endpoint=endpoint,
                            )
                        )
                        return results

        return results
