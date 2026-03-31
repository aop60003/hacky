# vibee_hacker/plugins/blackbox/csp_analysis.py
"""Content Security Policy analysis plugin."""

from __future__ import annotations

import re

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase


def _parse_csp(header: str) -> dict[str, list[str]]:
    """Parse CSP header into directive -> values dict."""
    directives: dict[str, list[str]] = {}
    for part in header.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if tokens:
            directives[tokens[0].lower()] = [t.lower() for t in tokens[1:]]
    return directives


class CspAnalysisPlugin(PluginBase):
    name = "csp_analysis"
    description = "Analyse Content-Security-Policy header for unsafe directives"
    category = "blackbox"
    phase = 2
    base_severity = Severity.MEDIUM
    detection_criteria = "CSP contains unsafe-inline, unsafe-eval, wildcard, data: URI, or is missing"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            try:
                resp = await client.get(target.url)
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

        results: list[Result] = []

        # Check Report-Only mode (informational)
        ro_header = resp.headers.get("Content-Security-Policy-Report-Only", "")
        csp_header = resp.headers.get("Content-Security-Policy", "")

        if not csp_header and not ro_header:
            results.append(Result(
                plugin_name=self.name,
                base_severity=Severity.HIGH,
                title="Content-Security-Policy header missing",
                description="The application does not set a Content-Security-Policy header, leaving it vulnerable to XSS and data injection attacks.",
                recommendation="Add a strict Content-Security-Policy header to all responses.",
                cwe_id="CWE-693",
                endpoint=target.url,
                rule_id="csp_missing",
            ))
            return results

        if ro_header and not csp_header:
            results.append(Result(
                plugin_name=self.name,
                base_severity=Severity.LOW,
                title="CSP in Report-Only mode",
                description="Content-Security-Policy is set to Report-Only mode and does not enforce the policy.",
                recommendation="Switch from Content-Security-Policy-Report-Only to Content-Security-Policy to enforce the policy.",
                cwe_id="CWE-693",
                endpoint=target.url,
                rule_id="csp_report_only",
            ))
            # Still analyse Report-Only directives for unsafe values
            csp_header = ro_header

        directives = _parse_csp(csp_header)
        script_src = directives.get("script-src", directives.get("default-src", []))

        if "'unsafe-inline'" in script_src:
            results.append(Result(
                plugin_name=self.name,
                base_severity=Severity.HIGH,
                title="CSP: unsafe-inline in script-src",
                description="The script-src directive allows 'unsafe-inline', which permits inline scripts and undermines XSS protection.",
                recommendation="Remove 'unsafe-inline' from script-src and use nonces or hashes instead.",
                cwe_id="CWE-693",
                endpoint=target.url,
                rule_id="csp_unsafe_inline",
            ))

        if "'unsafe-eval'" in script_src:
            results.append(Result(
                plugin_name=self.name,
                base_severity=Severity.HIGH,
                title="CSP: unsafe-eval in script-src",
                description="The script-src directive allows 'unsafe-eval', which permits eval() and similar dangerous functions.",
                recommendation="Remove 'unsafe-eval' from script-src.",
                cwe_id="CWE-693",
                endpoint=target.url,
                rule_id="csp_unsafe_eval",
            ))

        if "*" in script_src:
            results.append(Result(
                plugin_name=self.name,
                base_severity=Severity.HIGH,
                title="CSP: wildcard (*) in script-src",
                description="The script-src directive uses a wildcard (*), allowing scripts from any origin.",
                recommendation="Replace the wildcard with an explicit allowlist of trusted origins.",
                cwe_id="CWE-693",
                endpoint=target.url,
                rule_id="csp_wildcard_script_src",
            ))

        if any(v.startswith("data:") for v in script_src):
            results.append(Result(
                plugin_name=self.name,
                base_severity=Severity.MEDIUM,
                title="CSP: data: URI in script-src",
                description="The script-src directive allows data: URIs, which can be used to execute arbitrary scripts.",
                recommendation="Remove 'data:' from script-src.",
                cwe_id="CWE-693",
                endpoint=target.url,
                rule_id="csp_data_uri_script_src",
            ))

        if "default-src" not in directives:
            results.append(Result(
                plugin_name=self.name,
                base_severity=Severity.MEDIUM,
                title="CSP: missing default-src directive",
                description="The Content-Security-Policy header does not include a default-src directive, which acts as a fallback for unspecified resource types.",
                recommendation="Add a restrictive default-src directive (e.g., default-src 'none' or default-src 'self').",
                cwe_id="CWE-693",
                endpoint=target.url,
                rule_id="csp_missing_default_src",
            ))

        return results
