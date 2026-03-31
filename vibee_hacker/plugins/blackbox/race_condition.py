# vibee_hacker/plugins/blackbox/race_condition.py
"""Race condition detection plugin via concurrent request comparison."""

from __future__ import annotations

import asyncio
import json
import re
import shlex

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

RACE_URL_PATTERN = re.compile(r"/order|/transfer|/buy|/redeem|/coupon|/apply", re.I)
CONCURRENT_REQUESTS = 5


def _normalize(text: str) -> str:
    """Strip dynamic fields before comparing response bodies to avoid FPs."""
    # Remove timestamps
    text = re.sub(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[.\d]*Z?', 'TIMESTAMP', text)
    # Remove UUIDs
    text = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 'UUID', text)
    # Remove CSRF tokens, nonces, and similar dynamic fields
    text = re.sub(r'"(?:csrf|nonce|token|_token)":\s*"[^"]*"', '"DYNAMIC":"NORMALIZED"', text)
    return text


class RaceConditionPlugin(PluginBase):
    name = "race_condition"
    description = "Detect race conditions by sending concurrent identical requests and comparing responses"
    category = "blackbox"
    phase = 3
    base_severity = Severity.HIGH
    detection_criteria = "Concurrent responses differ (different IDs, amounts) indicating race condition"
    expected_evidence = "Multiple concurrent requests returned different response bodies"
    destructive_level = 2

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        if not RACE_URL_PATTERN.search(target.url):
            return []

        async def send_request(client: httpx.AsyncClient) -> httpx.Response | None:
            try:
                return await client.post(
                    target.url,
                    json={"action": "process"},
                    headers={"Content-Type": "application/json"},
                )
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return None

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            responses = await asyncio.gather(
                *[send_request(client) for _ in range(CONCURRENT_REQUESTS)]
            )

        valid_responses = [r for r in responses if r is not None]
        if len(valid_responses) < 2:
            return []

        # Compare normalized response bodies - if any differ, possible race condition
        bodies = [_normalize(r.text) for r in valid_responses]
        unique_bodies = set(bodies)

        if len(unique_bodies) > 1:
            return [Result(
                plugin_name=self.name,
                base_severity=self.base_severity,
                title="Possible race condition detected",
                description=(
                    f"Sending {CONCURRENT_REQUESTS} identical concurrent POST requests to "
                    f"'{target.url}' produced {len(unique_bodies)} different responses. "
                    f"This may indicate a race condition allowing duplicate processing, "
                    f"double-spending, or coupon reuse attacks."
                ),
                evidence=(
                    f"Sent {CONCURRENT_REQUESTS} concurrent requests, "
                    f"got {len(unique_bodies)} unique responses out of {len(valid_responses)} total"
                ),
                recommendation=(
                    "Implement atomic database transactions and proper locking mechanisms. "
                    "Use idempotency keys for financial transactions. "
                    "Apply rate limiting per user for sensitive operations."
                ),
                cwe_id="CWE-362",
                endpoint=target.url,
                curl_command=(
                    f"# Send {CONCURRENT_REQUESTS} concurrent requests:\n"
                    f"for i in $(seq 1 {CONCURRENT_REQUESTS}); do "
                    f"curl -X POST {shlex.quote(target.url)} "
                    f"-H 'Content-Type: application/json' "
                    f"-d '{{\"action\":\"process\"}}' & "
                    f"done; wait"
                ),
                rule_id="race_condition_detected",
            )]

        return []
