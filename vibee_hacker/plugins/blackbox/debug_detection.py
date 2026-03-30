# vibee_hacker/plugins/blackbox/debug_detection.py
"""Debug endpoint detection plugin."""

from __future__ import annotations

import re
import shlex
from urllib.parse import urljoin, urlparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

DEBUG_PATHS = [
    "/debug",
    "/console",
    "/__debug__/",
    "/telescope",
    "/_debugbar",
    "/elmah.axd",
]

DEBUG_PATTERNS = [
    re.compile(r"Traceback", re.I),
    re.compile(r"Django Debug", re.I),
    re.compile(r"Laravel", re.I),
    re.compile(r"stack trace", re.I),
    re.compile(r"SQLSTATE", re.I),
    re.compile(r"Exception in thread", re.I),
    re.compile(r"Fatal error", re.I),
    re.compile(r"PHPDebugBar", re.I),
]


def _base_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


class DebugDetectionPlugin(PluginBase):
    name = "debug_detection"
    description = "Detect exposed debug endpoints and debug information"
    category = "blackbox"
    phase = 2
    base_severity = Severity.HIGH
    detection_criteria = "Debug endpoint accessible with debug indicators in response"
    expected_evidence = "Traceback, stack trace, or framework debug page in response"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        base = _base_url(target.url)
        results: list[Result] = []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            for path in DEBUG_PATHS:
                endpoint = base + path
                try:
                    resp = await client.get(endpoint)
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                if resp.status_code == 404:
                    continue

                if len(resp.text) > 1_000_000:
                    continue

                for pattern in DEBUG_PATTERNS:
                    if pattern.search(resp.text):
                        results.append(Result(
                            plugin_name=self.name,
                            base_severity=self.base_severity,
                            title=f"Debug endpoint exposed: {path}",
                            description=(
                                f"A debug endpoint is accessible at {endpoint} and contains "
                                f"debug information (matched: {pattern.pattern})."
                            ),
                            evidence=f"Path: {path} | Status: {resp.status_code} | Pattern: {pattern.pattern}",
                            cwe_id="CWE-489",
                            endpoint=endpoint,
                            curl_command=f"curl {shlex.quote(endpoint)}",
                            rule_id="debug_endpoint_exposed",
                        ))
                        return results  # stop on first finding

        return results
