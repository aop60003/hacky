# vibee_hacker/plugins/blackbox/http_methods.py
"""Dangerous HTTP methods detection plugin."""

from __future__ import annotations

import shlex

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

DANGEROUS_METHODS = {"TRACE", "PUT", "DELETE", "CONNECT", "PATCH"}
TRACE_PROBE_HEADER = "X-Hacker-Probe"
TRACE_PROBE_VALUE = "vibee-check"


class HttpMethodsPlugin(PluginBase):
    name = "http_methods"
    description = "Detect dangerous HTTP methods (TRACE/PUT/DELETE) enabled on the server"
    category = "blackbox"
    phase = 2
    base_severity = Severity.MEDIUM
    detection_criteria = "OPTIONS response lists TRACE or other dangerous methods, or TRACE echoes request body"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        results: list[Result] = []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            # Step 1: OPTIONS request
            try:
                options_resp = await client.options(target.url)
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

            allow_header = options_resp.headers.get("Allow", "")
            allowed_methods = {m.strip().upper() for m in allow_header.split(",")}
            dangerous_found = allowed_methods & DANGEROUS_METHODS

            # Step 2: Directly test TRACE method
            try:
                trace_resp = await client.request(
                    "TRACE",
                    target.url,
                    headers={TRACE_PROBE_HEADER: TRACE_PROBE_VALUE},
                )
                trace_echoed = (
                    trace_resp.status_code < 400
                    and TRACE_PROBE_VALUE in trace_resp.text
                )
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                trace_echoed = False

            # Report TRACE via Allow header
            if "TRACE" in dangerous_found:
                results.append(Result(
                    plugin_name=self.name,
                    base_severity=Severity.MEDIUM,
                    title="Dangerous HTTP method enabled: TRACE (XST risk)",
                    description=(
                        "The server advertises TRACE in the Allow header. TRACE can be used in "
                        "Cross-Site Tracing (XST) attacks to steal cookies and authentication headers."
                    ),
                    recommendation="Disable the TRACE method in the server configuration.",
                    evidence=f"Allow: {allow_header}",
                    cwe_id="CWE-16",
                    endpoint=target.url,
                    curl_command=f"curl -X OPTIONS {shlex.quote(target.url)} -i",
                    rule_id="http_method_trace_allowed",
                ))

            # Report TRACE body reflection (XST confirmed)
            if trace_echoed and not any(r.rule_id == "http_method_trace_xst" for r in results):
                results.append(Result(
                    plugin_name=self.name,
                    base_severity=Severity.HIGH,
                    title="TRACE method echoes request body (XST confirmed)",
                    description=(
                        "The server responds to TRACE requests and echoes back the request, "
                        "including headers. This enables Cross-Site Tracing (XST) attacks."
                    ),
                    recommendation="Disable the TRACE method in the server configuration.",
                    evidence=f"TRACE response status: {trace_resp.status_code}, probe header echoed",
                    cwe_id="CWE-16",
                    endpoint=target.url,
                    curl_command=f"curl -X TRACE {shlex.quote(target.url)} -H '{TRACE_PROBE_HEADER}: {TRACE_PROBE_VALUE}'",
                    rule_id="http_method_trace_xst",
                ))

            # Report other dangerous methods
            for method in sorted(dangerous_found - {"TRACE"}):
                results.append(Result(
                    plugin_name=self.name,
                    base_severity=Severity.MEDIUM,
                    title=f"Dangerous HTTP method enabled: {method}",
                    description=(
                        f"The server advertises {method} in the Allow header. "
                        "This method may allow unauthorized data modification or deletion."
                    ),
                    recommendation=f"Disable the {method} method unless required by the API.",
                    evidence=f"Allow: {allow_header}",
                    cwe_id="CWE-16",
                    endpoint=target.url,
                    curl_command=f"curl -X OPTIONS {shlex.quote(target.url)} -i",
                    rule_id=f"http_method_{method.lower()}_allowed",
                ))

        return results
