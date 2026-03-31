# vibee_hacker/plugins/blackbox/http_smuggling.py
"""HTTP request smuggling (CL.TE) detection plugin."""

from __future__ import annotations

import shlex

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

# HTTP status codes that suggest server-side framing confusion
SMUGGLING_INDICATOR_CODES = {400, 408, 413, 500, 501, 502, 503}


class HttpSmugglingPlugin(PluginBase):
    name = "http_smuggling"
    description = "Detect HTTP request smuggling vulnerability via CL.TE ambiguous framing"
    category = "blackbox"
    phase = 3
    base_severity = Severity.CRITICAL
    detection_criteria = (
        "Server returns error (4xx/5xx) or unexpected response to a request "
        "with both Content-Length and Transfer-Encoding: chunked headers"
    )
    expected_evidence = "HTTP 400/408/500 or chunked-framing error in response to CL.TE probe"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        normal_body = b"a=1"
        normal_headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(len(normal_body)),
        }

        # CL.TE probe: Content-Length says 5 bytes, but body is chunked with different length
        # This creates ambiguity between front-end (uses CL) and back-end (uses TE)
        probe_body = b"0\r\n\r\n"  # chunked terminator as body
        probe_headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(len(probe_body)),
            "Transfer-Encoding": "chunked",
            "Connection": "keep-alive",
        }

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            try:
                baseline = await client.post(
                    target.url,
                    content=normal_body,
                    headers=normal_headers,
                )
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

            # If the server already rejects normal POSTs with 400/500, skip to avoid FP
            if baseline.status_code in SMUGGLING_INDICATOR_CODES:
                return []

            try:
                resp = await client.post(
                    target.url,
                    content=probe_body,
                    headers=probe_headers,
                )
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

        # Only report if probe response is DIFFERENT from baseline AND in the suspicious set
        if resp.status_code in SMUGGLING_INDICATOR_CODES and resp.status_code != baseline.status_code:
            return [Result(
                plugin_name=self.name,
                base_severity=self.base_severity,
                title="HTTP request smuggling (CL.TE) potentially present",
                description=(
                    f"The server at {target.url} returned HTTP {resp.status_code} "
                    f"in response to a request with ambiguous Content-Length and "
                    f"Transfer-Encoding: chunked headers. This may indicate the server "
                    f"is vulnerable to CL.TE HTTP request smuggling."
                ),
                evidence=(
                    f"URL: {target.url} | Probe: CL.TE ambiguous framing | "
                    f"Baseline status: {baseline.status_code} | "
                    f"Probe response status: {resp.status_code}"
                ),
                cwe_id="CWE-444",
                endpoint=target.url,
                curl_command=(
                    f"curl -v -X POST {shlex.quote(target.url)} "
                    f"-H 'Content-Length: 5' "
                    f"-H 'Transfer-Encoding: chunked' "
                    f"--data $'0\\r\\n\\r\\n'"
                ),
                rule_id="http_smuggling_clte",
            )]

        return []
