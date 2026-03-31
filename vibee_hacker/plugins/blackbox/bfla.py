# vibee_hacker/plugins/blackbox/bfla.py
"""Broken Function Level Authorization (BFLA) detection plugin."""

from __future__ import annotations

import json
import re
import shlex
from urllib.parse import urlparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

ADMIN_PATHS = [
    "/admin",
    "/api/admin",
    "/api/admin/users",
    "/api/v1/admin",
    "/dashboard/admin",
]

# Sensitive JSON keys whose presence indicates real data exposure (not just HTML)
SENSITIVE_KEYS = re.compile(
    r'"(email|password|role|token|secret|api_key|access_token|refresh_token)"',
    re.I,
)

# Minimum body length to consider a response "substantial"
MIN_BODY_LENGTH = 10


def _base_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


class BflaPlugin(PluginBase):
    name = "bfla"
    description = "Detect Broken Function Level Authorization — unauthorized access to admin-level endpoints"
    category = "blackbox"
    phase = 3
    base_severity = Severity.HIGH
    detection_criteria = (
        "Admin-like path returns 200 with JSON Content-Type AND body contains sensitive keys "
        "(email, password, role, token, etc.) — unauthenticated or low-privilege"
    )
    expected_evidence = "HTTP 200 JSON response with sensitive data keys from admin endpoint without authentication"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        base = _base_url(target.url)
        results: list[Result] = []

        async with httpx.AsyncClient(
            verify=target.verify_ssl,
            timeout=10,
            follow_redirects=False,
        ) as client:
            for path in ADMIN_PATHS:
                endpoint = base + path
                try:
                    resp = await client.get(endpoint)
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                if resp.status_code != 200:
                    continue

                if len(resp.text) > 1_000_000:
                    continue

                if len(resp.text.strip()) < MIN_BODY_LENGTH:
                    continue

                # Only report if response is JSON with sensitive keys — skip plain HTML 200s
                content_type = resp.headers.get("content-type", "")
                if "application/json" not in content_type:
                    continue
                if not SENSITIVE_KEYS.search(resp.text):
                    continue

                results.append(Result(
                    plugin_name=self.name,
                    base_severity=self.base_severity,
                    title=f"BFLA: admin endpoint accessible without authorization — {path}",
                    description=(
                        f"The admin-level endpoint {endpoint} returned HTTP 200 with a substantial "
                        f"response body without requiring authentication. This indicates Broken "
                        f"Function Level Authorization (BFLA) where function-level access controls "
                        f"are missing or improperly enforced."
                    ),
                    evidence=(
                        f"Path: {path} | Status: {resp.status_code} | "
                        f"Body length: {len(resp.text)} bytes"
                    ),
                    cwe_id="CWE-285",
                    endpoint=endpoint,
                    curl_command=f"curl {shlex.quote(endpoint)}",
                    rule_id="bfla_admin_access",
                ))
                return results  # Stop on first finding

        return results
