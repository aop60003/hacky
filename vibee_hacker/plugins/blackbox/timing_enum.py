"""Plugin: Timing-Based Username Enumeration (blackbox)."""
from __future__ import annotations

import asyncio
import time
from urllib.parse import urlparse, urlunparse

import httpx

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

# Usernames to probe: mix of common/likely valid vs random/invalid
LIKELY_VALID_USERNAMES = ["admin", "administrator", "user", "root", "test"]
LIKELY_INVALID_USERNAMES = [
    "vibee_nonexistent_user_xk9z",
    "zzz_no_such_user_abc",
    "vibee_fake_8x7q",
]

LOGIN_PATHS = [
    "/login",
    "/api/login",
    "/auth/login",
    "/signin",
    "/api/signin",
    "/user/login",
    "/account/login",
]

# Threshold: if valid usernames are consistently N seconds slower than invalid,
# it's likely a timing oracle
TIMING_THRESHOLD_SECONDS = 0.3
MEASUREMENTS = 3  # Number of timing measurements per username


class TimingEnumPlugin(PluginBase):
    name = "timing_enum"
    description = "Detect timing-based username enumeration by comparing response times for valid vs invalid usernames"
    category = "blackbox"
    phase = 3
    base_severity = Severity.MEDIUM

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        parsed = urlparse(target.url)
        base = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
        results: list[Result] = []

        # Find a login endpoint
        login_endpoint: str | None = None
        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            for path in LOGIN_PATHS:
                endpoint = base + path
                try:
                    probe = await client.get(endpoint)
                    if probe.status_code not in (404, 405, 410):
                        login_endpoint = endpoint
                        break
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

        if not login_endpoint:
            # Fallback to target URL
            login_endpoint = target.url

        async def measure_time(client: httpx.AsyncClient, username: str) -> float:
            """Measure average response time for a login attempt with the given username."""
            times: list[float] = []
            for _ in range(MEASUREMENTS):
                start = time.monotonic()
                try:
                    await client.post(
                        login_endpoint,
                        data={"username": username, "password": "vibee_timing_probe_xk9z!@#"},
                        timeout=10,
                    )
                except (httpx.TransportError, httpx.TimeoutException):
                    pass
                elapsed = time.monotonic() - start
                times.append(elapsed)
                await asyncio.sleep(0.05)
            return sum(times) / len(times) if times else 0.0

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=15) as client:
            # Measure timing for invalid usernames
            invalid_times: list[float] = []
            for username in LIKELY_INVALID_USERNAMES[:2]:
                t = await measure_time(client, username)
                invalid_times.append(t)

            # Measure timing for likely valid usernames
            valid_times: list[tuple[str, float]] = []
            for username in LIKELY_VALID_USERNAMES[:3]:
                t = await measure_time(client, username)
                valid_times.append((username, t))

        if not invalid_times or not valid_times:
            return []

        avg_invalid = sum(invalid_times) / len(invalid_times)

        # Check for significant timing difference
        for username, avg_valid in valid_times:
            diff = avg_valid - avg_invalid
            if diff > TIMING_THRESHOLD_SECONDS:
                results.append(
                    Result(
                        plugin_name=self.name,
                        base_severity=Severity.MEDIUM,
                        title="Timing-Based Username Enumeration",
                        description=(
                            f"Login endpoint at {login_endpoint} responds {diff:.3f}s slower for "
                            f"username '{username}' compared to random usernames (avg: {avg_valid:.3f}s vs {avg_invalid:.3f}s). "
                            "This timing difference may allow username enumeration."
                        ),
                        evidence=(
                            f"Username '{username}': avg {avg_valid:.3f}s | "
                            f"Invalid username: avg {avg_invalid:.3f}s | "
                            f"Difference: {diff:.3f}s (threshold: {TIMING_THRESHOLD_SECONDS}s)"
                        ),
                        recommendation=(
                            "Use constant-time comparison for authentication. "
                            "Return identical responses and delays for valid and invalid usernames. "
                            "Implement rate limiting to prevent enumeration."
                        ),
                        cwe_id="CWE-203",
                        rule_id="timing_username_enum",
                        endpoint=login_endpoint,
                    )
                )
                break  # Report once

        return results
