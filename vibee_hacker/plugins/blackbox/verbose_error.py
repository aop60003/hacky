# vibee_hacker/plugins/blackbox/verbose_error.py
"""Verbose error disclosure detection plugin."""

from __future__ import annotations

import re
import shlex
from urllib.parse import urlparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

# Paths designed to trigger error responses
ERROR_PATHS = [
    "/this-path-does-not-exist-at-all-12345",
    "/api/..%00../etc/passwd",
    "/api/items?id=not_a_number&page=abc",
]

VERBOSE_ERROR_PATTERNS = [
    re.compile(r"Traceback", re.I),
    re.compile(r"stack trace", re.I),
    re.compile(r"SQLSTATE", re.I),
    re.compile(r"at .+\.(?:java|py|rb|php|cs|js|ts):\d+", re.I),
    re.compile(r"(?:/usr/(?:local/)?(?:lib|share|src)|/var/(?:www|log))/", re.I),
    re.compile(r"C:\\", re.I),
    re.compile(r"Exception in", re.I),
]


def _base_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


class VerboseErrorPlugin(PluginBase):
    name = "verbose_error"
    description = "Detect verbose error messages that disclose internal implementation details"
    category = "blackbox"
    phase = 3
    base_severity = Severity.MEDIUM
    detection_criteria = "Error response contains stack traces, file paths, or internal error details"
    expected_evidence = "Traceback, stack trace, SQLSTATE, file path, or exception details in response"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        base = _base_url(target.url)
        results: list[Result] = []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            for path in ERROR_PATHS:
                endpoint = base + path
                try:
                    resp = await client.get(endpoint)
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                if len(resp.text) > 1_000_000:
                    continue

                for pattern in VERBOSE_ERROR_PATTERNS:
                    if pattern.search(resp.text):
                        results.append(Result(
                            plugin_name=self.name,
                            base_severity=self.base_severity,
                            title="Verbose error disclosure",
                            description=(
                                f"The application returns verbose error messages at {endpoint} that "
                                f"disclose internal implementation details such as stack traces, "
                                f"file paths, or exception information."
                            ),
                            evidence=f"Path: {path} | Status: {resp.status_code} | Pattern: {pattern.pattern}",
                            cwe_id="CWE-209",
                            endpoint=endpoint,
                            curl_command=f"curl {shlex.quote(endpoint)}",
                            rule_id="verbose_error_disclosure",
                        ))
                        return results  # Stop on first finding

        return results
