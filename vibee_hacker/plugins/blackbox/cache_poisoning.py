# vibee_hacker/plugins/blackbox/cache_poisoning.py
"""Cache poisoning via unkeyed header reflection detection plugin."""

from __future__ import annotations

import shlex

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

EVIL_HOST = "evil-cache-poison.com"

# Headers that are commonly unkeyed and can affect response content
POISON_HEADERS = {
    "X-Forwarded-Host": EVIL_HOST,
    "X-Original-URL": f"https://{EVIL_HOST}/",
    "X-Forwarded-Scheme": "https",
}

# Response headers that indicate caching is active
CACHE_INDICATOR_HEADERS = ["x-cache", "age", "cf-cache-status", "x-drupal-cache", "x-varnish"]


class CachePoisoningPlugin(PluginBase):
    name = "cache_poisoning"
    description = "Detect cache poisoning risk via unkeyed header reflection in cacheable responses"
    category = "blackbox"
    phase = 3
    base_severity = Severity.HIGH
    detection_criteria = (
        "Injected X-Forwarded-Host / X-Original-URL value reflected in response body or headers "
        "AND response shows cache indicators"
    )
    expected_evidence = "Evil host value reflected in cached HTTP response"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        results: list[Result] = []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            try:
                resp = await client.get(
                    target.url,
                    headers=POISON_HEADERS,
                )
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

            if len(resp.text) > 1_000_000:
                return []

            # Check if evil host is reflected in body
            body_reflected = EVIL_HOST in resp.text

            # Check if evil host is reflected in response headers (e.g. Location)
            location = resp.headers.get("location", "")
            header_reflected = EVIL_HOST in location

            if not (body_reflected or header_reflected):
                return []

            # Check if response is cacheable (presence of cache-related headers)
            resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            cache_control = resp_headers_lower.get("cache-control", "")

            # Skip entirely if explicitly non-cacheable
            if "no-store" in cache_control or "private" in cache_control:
                return []

            is_cacheable = any(h in resp_headers_lower for h in CACHE_INDICATOR_HEADERS)
            if "public" in cache_control or "max-age" in cache_control:
                is_cacheable = True

            # Only report if we can confirm the response is cacheable
            if not is_cacheable:
                return []

            reflection_location = "response body" if body_reflected else "Location header"

            results.append(Result(
                plugin_name=self.name,
                base_severity=self.base_severity,
                title="Cache poisoning: unkeyed header reflected in response",
                description=(
                    f"The application reflects the injected X-Forwarded-Host value '{EVIL_HOST}' "
                    f"in the {reflection_location} (cacheable response confirmed). An attacker can inject a "
                    f"malicious host and have the poisoned response served to other users from cache, "
                    f"enabling phishing, credential theft, or malicious script injection."
                ),
                evidence=(
                    f"'{EVIL_HOST}' reflected in {reflection_location} | "
                    f"Cacheable response confirmed | Status: {resp.status_code}"
                ),
                cwe_id="CWE-444",
                endpoint=target.url,
                curl_command=(
                    f"curl {shlex.quote(target.url)} "
                    f"-H 'X-Forwarded-Host: {EVIL_HOST}' "
                    f"-H 'X-Original-URL: https://{EVIL_HOST}/'"
                ),
                rule_id="cache_poisoning_header_reflected",
            ))

        return results
