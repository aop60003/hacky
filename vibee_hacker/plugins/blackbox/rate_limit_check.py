# vibee_hacker/plugins/blackbox/rate_limit_check.py
"""Rate limit absence detection plugin."""

from __future__ import annotations

import re
import shlex

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

AUTH_URL_PATTERN = re.compile(r"login|auth|signin|sign-in|password", re.I)

REQUEST_COUNT = 20
RATE_LIMIT_HEADERS = ["x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset", "retry-after"]


class RateLimitCheckPlugin(PluginBase):
    name = "rate_limit_check"
    description = "Detect absence of rate limiting on authentication endpoints"
    category = "blackbox"
    phase = 3
    base_severity = Severity.HIGH
    detection_criteria = "No 429 response or rate limit headers after 20 rapid requests to auth endpoint"
    expected_evidence = "All 20 requests returned non-429 status without rate limit headers"
    destructive_level = 2

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        # Only probe auth-related URLs
        if not AUTH_URL_PATTERN.search(target.url):
            return []

        results: list[Result] = []
        rate_limited = False

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            for i in range(REQUEST_COUNT):
                try:
                    resp = await client.post(
                        target.url,
                        json={"username": "test@example.com", "password": "wrongpassword"},
                        headers={"Content-Type": "application/json"},
                    )
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                # Check for rate limit response code
                if resp.status_code == 429:
                    rate_limited = True
                    break

                # Check for rate limit headers
                response_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
                for header in RATE_LIMIT_HEADERS:
                    if header in response_headers_lower:
                        rate_limited = True
                        break

                if rate_limited:
                    break

        if not rate_limited:
            results.append(Result(
                plugin_name=self.name,
                base_severity=self.base_severity,
                title="Rate limiting absent on authentication endpoint",
                description=(
                    f"No rate limiting was detected after sending {REQUEST_COUNT} rapid requests "
                    f"to the authentication endpoint {target.url}. "
                    f"This allows brute force and credential stuffing attacks."
                ),
                evidence=(
                    f"Sent {REQUEST_COUNT} requests with no 429 response or "
                    f"rate limit headers (X-RateLimit-*) observed"
                ),
                cwe_id="CWE-770",
                endpoint=target.url,
                curl_command=(
                    f"for i in $(seq 1 {REQUEST_COUNT}); do "
                    f"curl -X POST {shlex.quote(target.url)} "
                    f"-H 'Content-Type: application/json' "
                    f"-d '{{\"username\":\"test@example.com\",\"password\":\"wrong\"}}'; "
                    f"done"
                ),
                rule_id="rate_limit_absent",
            ))

        return results
