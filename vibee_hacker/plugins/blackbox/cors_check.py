# vibee_hacker/plugins/blackbox/cors_check.py
"""CORS misconfiguration check plugin."""

from __future__ import annotations

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

EVIL_ORIGINS = [
    "https://evil.com",
    "https://example.com.evil.com",
    "null",
]


class CorsCheckPlugin(PluginBase):
    name = "cors_check"
    description = "Check for CORS misconfigurations"
    category = "blackbox"
    phase = 2
    base_severity = Severity.HIGH
    detection_criteria = "Server reflects arbitrary Origin or uses wildcard with credentials"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        # Build list of URLs to test: start URL + crawled URLs + crawled API endpoints
        urls_to_test: list[str] = [target.url]
        if context:
            for crawled_url in (context.crawl_urls or [])[:10]:
                if crawled_url not in urls_to_test:
                    urls_to_test.append(crawled_url)
            # crawl_parameters keys are URLs discovered via JS fetch/axios patterns
            for api_url in list((context.crawl_parameters or {}).keys())[:10]:
                if api_url not in urls_to_test:
                    urls_to_test.append(api_url)

        results = []
        seen_rule_ids: set[str] = set()

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            for test_url in urls_to_test:
                for evil_origin in EVIL_ORIGINS:
                    try:
                        resp = await client.get(
                            test_url, headers={"Origin": evil_origin}
                        )
                    except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                        continue

                    acao = resp.headers.get("Access-Control-Allow-Origin", "")
                    acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

                    if acao == evil_origin and "cors_origin_reflected" not in seen_rule_ids:
                        seen_rule_ids.add("cors_origin_reflected")
                        results.append(Result(
                            plugin_name=self.name,
                            base_severity=Severity.HIGH,
                            title="CORS: Arbitrary Origin reflected",
                            description=f"Server reflects attacker-controlled Origin header: {evil_origin}",
                            recommendation="Validate Origin against an allowlist instead of reflecting it.",
                            cwe_id="CWE-942",
                            endpoint=test_url,
                            rule_id="cors_origin_reflected",
                        ))

                    if acao == "*" and acac == "true" and "cors_wildcard_credentials" not in seen_rule_ids:
                        seen_rule_ids.add("cors_wildcard_credentials")
                        results.append(Result(
                            plugin_name=self.name,
                            base_severity=Severity.CRITICAL,
                            title="CORS: Wildcard with Credentials",
                            description="Access-Control-Allow-Origin: * combined with Allow-Credentials: true",
                            recommendation="Never combine wildcard origin with credentials.",
                            cwe_id="CWE-942",
                            endpoint=test_url,
                            rule_id="cors_wildcard_credentials",
                        ))

                    if acao == "null" and "cors_null_origin" not in seen_rule_ids:
                        seen_rule_ids.add("cors_null_origin")
                        results.append(Result(
                            plugin_name=self.name,
                            base_severity=Severity.MEDIUM,
                            title="CORS: null Origin allowed",
                            description="Server allows null origin, exploitable via sandboxed iframes.",
                            recommendation="Do not allow null origin in CORS configuration.",
                            cwe_id="CWE-942",
                            endpoint=test_url,
                            rule_id="cors_null_origin",
                        ))

                    # Once all unique findings discovered, no need to check more URLs
                    if len(seen_rule_ids) >= 3:
                        return results

        return results
