"""Race condition detection via concurrent request flooding."""

from __future__ import annotations

import asyncio
import time
from urllib.parse import urlparse

import httpx

from vibee_hacker.core.plugin_base import PluginBase
from vibee_hacker.core.models import Result, Severity, Target, InterPhaseContext


class RaceConditionPlugin(PluginBase):
    name = "race_condition"
    description = "Detect race conditions via concurrent request analysis"
    category = "blackbox"
    phase = 3
    destructive_level = 2  # sends many concurrent requests
    base_severity = Severity.HIGH

    def is_applicable(self, target: Target) -> bool:
        return bool(target.url)

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        results = []

        # Collect endpoints to test from context
        urls_to_test = [target.url]
        if context:
            for url in (getattr(context, "crawl_urls", None) or [])[:5]:
                if url not in urls_to_test:
                    urls_to_test.append(url)

        async with httpx.AsyncClient(
            verify=getattr(target, "verify_ssl", True),
            timeout=10,
            follow_redirects=True,
        ) as client:
            for url in urls_to_test:
                result = await self._test_race(client, url)
                if result:
                    results.append(result)
                if len(results) >= 5:
                    break

        return results

    async def _test_race(self, client: httpx.AsyncClient, url: str) -> Result | None:
        """Send concurrent requests and analyze for race condition indicators."""
        CONCURRENCY = 10

        # Phase 1: Baseline — single request
        try:
            baseline = await client.get(url)
            baseline_status = baseline.status_code
        except (httpx.TransportError, httpx.InvalidURL):
            return None

        # Phase 2: Concurrent burst
        async def single_request() -> dict | None:
            try:
                start = time.monotonic()
                resp = await client.get(url)
                elapsed = time.monotonic() - start
                return {
                    "status": resp.status_code,
                    "length": len(resp.content),
                    "time": elapsed,
                    "body": resp.text[:500],
                }
            except Exception:
                return None

        tasks = [single_request() for _ in range(CONCURRENCY)]
        burst_results = await asyncio.gather(*tasks)
        burst_results = [r for r in burst_results if r is not None]

        if len(burst_results) < 3:
            return None

        # Phase 3: Analyze for anomalies
        statuses = [r["status"] for r in burst_results]
        lengths = [r["length"] for r in burst_results]
        times = [r["time"] for r in burst_results]

        # Check for inconsistent responses (different status codes)
        unique_statuses = set(statuses)
        if len(unique_statuses) > 1 and baseline_status in unique_statuses:
            return Result(
                plugin_name=self.name,
                base_severity=Severity.HIGH,
                title=f"Race condition: inconsistent responses at {urlparse(url).path}",
                description=(
                    f"Concurrent requests produced different status codes: {unique_statuses}. "
                    f"This may indicate a race condition or TOCTOU vulnerability."
                ),
                endpoint=url,
                rule_id="race_condition_status_inconsistency",
                cwe_id="CWE-362",
                evidence=f"Statuses: {statuses}",
                recommendation="Implement proper locking/serialization for state-changing operations.",
            )

        # Check for significant response length variance (>20% difference)
        if lengths:
            avg_length = sum(lengths) / len(lengths)
            if avg_length > 0:
                max_diff = max(abs(length - avg_length) for length in lengths)
                variance_pct = (max_diff / avg_length) * 100
                if variance_pct > 20:
                    return Result(
                        plugin_name=self.name,
                        base_severity=Severity.MEDIUM,
                        title=f"Possible race condition: response length variance at {urlparse(url).path}",
                        description=(
                            f"Concurrent requests show {variance_pct:.0f}% response length variance. "
                            f"Average: {avg_length:.0f}, range: {min(lengths)}-{max(lengths)}."
                        ),
                        endpoint=url,
                        rule_id="race_condition_length_variance",
                        cwe_id="CWE-362",
                        evidence=f"Lengths: {lengths}",
                        recommendation="Review endpoint for concurrent access issues.",
                    )

        # Check for significant timing anomalies (one request much slower)
        if times:
            avg_time = sum(times) / len(times)
            if avg_time > 0:
                max_time = max(times)
                if max_time > avg_time * 3 and max_time > 1.0:
                    return Result(
                        plugin_name=self.name,
                        base_severity=Severity.LOW,
                        title=f"Timing anomaly under concurrent load at {urlparse(url).path}",
                        description=(
                            f"One request took {max_time:.2f}s vs average {avg_time:.2f}s under concurrent load. "
                            f"May indicate resource contention."
                        ),
                        endpoint=url,
                        rule_id="race_condition_timing_anomaly",
                        cwe_id="CWE-362",
                        evidence=f"Times: {[f'{t:.3f}s' for t in times]}",
                        recommendation="Investigate resource contention under concurrent access.",
                    )

        return None
