# vibee_hacker/plugins/blackbox/broken_auth_flow.py
"""Broken authentication flow detection plugin."""

from __future__ import annotations

import shlex

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

MIN_BODY_LENGTH = 100  # bytes threshold for "substantial body"

AUTH_PROBES = [
    ("no_token", {}),
    ("empty_bearer", {"Authorization": "Bearer "}),
    ("invalid_bearer", {"Authorization": "Bearer invalid"}),
]


class BrokenAuthPlugin(PluginBase):
    name = "broken_auth_flow"
    description = "Detect broken authentication via requests without valid tokens"
    category = "blackbox"
    phase = 3
    base_severity = Severity.CRITICAL
    detection_criteria = "200 response with substantial body returned without valid auth token"
    expected_evidence = "HTTP 200 with >100 char body received without Authorization header"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        results: list[Result] = []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            for probe_id, headers in AUTH_PROBES:
                try:
                    resp = await client.get(target.url, headers=headers)
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    return []

                if resp.status_code == 200 and len(resp.text) > MIN_BODY_LENGTH:
                    probe_label = {
                        "no_token": "no Authorization header",
                        "empty_bearer": "empty Bearer token",
                        "invalid_bearer": "invalid Bearer token",
                    }.get(probe_id, probe_id)

                    curl_headers = " ".join(
                        f"-H {shlex.quote(f'{k}: {v}')}" for k, v in headers.items()
                    )
                    curl_cmd = f"curl {curl_headers} {shlex.quote(target.url)}".strip()

                    results.append(Result(
                        plugin_name=self.name,
                        base_severity=self.base_severity,
                        title="Broken authentication: endpoint accessible without valid token",
                        description=(
                            f"Endpoint {target.url} returned HTTP 200 with "
                            f"{len(resp.text)} chars of body content using {probe_label}."
                        ),
                        evidence=(
                            f"Probe: {probe_label} | Status: {resp.status_code} | "
                            f"Body length: {len(resp.text)}"
                        ),
                        cwe_id="CWE-287",
                        endpoint=target.url,
                        curl_command=curl_cmd,
                        rule_id="broken_auth_no_token",
                    ))
                    return results  # stop on first confirmed bypass

        return results
