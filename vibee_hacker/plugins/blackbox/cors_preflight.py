# vibee_hacker/plugins/blackbox/cors_preflight.py
"""CORS Preflight Bypass detection plugin."""

from __future__ import annotations

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

EVIL_ORIGIN = "https://evil-attacker.com"

# Simple request methods that skip preflight but still send credentials
SIMPLE_METHODS = ["GET", "POST"]

# API paths worth probing for CORS misconfig beyond the target URL
API_PROBE_PATHS = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/data",
    "/api/user",
    "/api/me",
    "/graphql",
]


class CorsPreflightPlugin(PluginBase):
    name = "cors_preflight"
    description = (
        "CORS Preflight Bypass — send cross-origin simple requests (no OPTIONS) "
        "and check if ACAO header reflects attacker origin with credentials"
    )
    category = "blackbox"
    phase = 2
    base_severity = Severity.HIGH
    destructive_level = 0
    detection_criteria = (
        "Server sets Access-Control-Allow-Origin to the attacker's origin "
        "AND Access-Control-Allow-Credentials: true on a simple cross-origin request"
    )
    expected_evidence = "ACAO header reflects evil origin with credentials flag"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        from urllib.parse import urlparse
        parsed_base = urlparse(target.url)
        base_url = f"{parsed_base.scheme}://{parsed_base.netloc}"

        urls_to_test: list[str] = [target.url]
        if context:
            for crawled_url in (context.crawl_urls or [])[:10]:
                if crawled_url not in urls_to_test:
                    urls_to_test.append(crawled_url)

        for probe_path in API_PROBE_PATHS:
            probe_url = base_url + probe_path
            if probe_url not in urls_to_test:
                urls_to_test.append(probe_url)

        results: list[Result] = []
        seen_rules: set[str] = set()

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            for test_url in urls_to_test:
                for method in SIMPLE_METHODS:
                    try:
                        if method == "GET":
                            resp = await client.get(
                                test_url,
                                headers={"Origin": EVIL_ORIGIN},
                            )
                        else:
                            resp = await client.post(
                                test_url,
                                headers={
                                    "Origin": EVIL_ORIGIN,
                                    "Content-Type": "application/x-www-form-urlencoded",
                                },
                                content=b"",
                            )
                    except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                        continue

                    acao = resp.headers.get("Access-Control-Allow-Origin", "")
                    acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

                    # Most dangerous: reflects evil origin + credentials
                    if acao == EVIL_ORIGIN and acac == "true":
                        rule = "cors_preflight_bypass_with_credentials"
                        if rule not in seen_rules:
                            seen_rules.add(rule)
                            results.append(Result(
                                plugin_name=self.name,
                                base_severity=Severity.CRITICAL,
                                title="CORS: Cross-origin request with credentials accepted (preflight bypassed)",
                                description=(
                                    f"The server reflects the attacker-controlled origin "
                                    f"'{EVIL_ORIGIN}' in Access-Control-Allow-Origin AND sets "
                                    f"Access-Control-Allow-Credentials: true on a simple "
                                    f"{method} request (no OPTIONS preflight required). "
                                    f"This allows cross-origin reads of authenticated responses."
                                ),
                                evidence=(
                                    f"ACAO: {acao} | ACAC: {acac} | "
                                    f"Method: {method} | URL: {test_url}"
                                ),
                                recommendation=(
                                    "Validate the Origin header against a strict allowlist. "
                                    "Never reflect arbitrary Origins when credentials are allowed."
                                ),
                                cwe_id="CWE-346",
                                endpoint=test_url,
                                rule_id="cors_preflight_bypass",
                            ))

                    # Reflected origin without credentials is still a finding
                    elif acao == EVIL_ORIGIN:
                        rule = "cors_preflight_origin_reflected"
                        if rule not in seen_rules:
                            seen_rules.add(rule)
                            results.append(Result(
                                plugin_name=self.name,
                                base_severity=Severity.HIGH,
                                title="CORS: Attacker origin reflected without preflight",
                                description=(
                                    f"The server reflects the attacker-controlled origin "
                                    f"'{EVIL_ORIGIN}' in Access-Control-Allow-Origin on a "
                                    f"simple {method} request. Without a strict allowlist, "
                                    f"any origin can read non-credentialed cross-origin responses."
                                ),
                                evidence=(
                                    f"ACAO: {acao} | ACAC: {acac} | "
                                    f"Method: {method} | URL: {test_url}"
                                ),
                                recommendation=(
                                    "Validate the Origin header against a strict allowlist."
                                ),
                                cwe_id="CWE-346",
                                endpoint=test_url,
                                rule_id="cors_preflight_bypass",
                            ))

                    if len(seen_rules) >= 2:
                        return results

        return results
