# vibee_hacker/plugins/blackbox/crlf_injection.py
"""CRLF injection detection plugin."""

from __future__ import annotations

import shlex
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

CRLF_PAYLOAD = "%0d%0aX-Injected:true"
INJECTED_HEADER = "x-injected"


class CrlfInjectionPlugin(PluginBase):
    name = "crlf_injection"
    description = "Detect CRLF injection via URL parameter manipulation"
    category = "blackbox"
    phase = 3
    base_severity = Severity.HIGH
    detection_criteria = "X-Injected header appears in response after injecting CRLF sequence"
    expected_evidence = "X-Injected header present in HTTP response"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        parsed = urlparse(target.url)
        params = parse_qs(parsed.query)
        if not params:
            return []

        results: list[Result] = []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10, follow_redirects=False) as client:
            for param_name, values in params.items():
                original_value = values[0] if values else ""
                injected_value = original_value + CRLF_PAYLOAD
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param_name] = injected_value
                test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

                try:
                    resp = await client.get(test_url)
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                if len(resp.text) > 1_000_000:
                    continue

                headers_lower = {k.lower(): v for k, v in resp.headers.items()}
                if INJECTED_HEADER in headers_lower:
                    results.append(Result(
                        plugin_name=self.name,
                        base_severity=self.base_severity,
                        title=f"CRLF injection via parameter '{param_name}'",
                        description=(
                            f"CRLF injection in parameter '{param_name}' caused "
                            f"header injection: {INJECTED_HEADER}: {headers_lower[INJECTED_HEADER]}"
                        ),
                        evidence=f"X-Injected header found in response | Param: {param_name} | Payload: {CRLF_PAYLOAD}",
                        cwe_id="CWE-113",
                        endpoint=test_url,
                        param_name=param_name,
                        curl_command=f"curl {shlex.quote(test_url)}",
                        rule_id="crlf_header_injection",
                    ))
                    return results

        return results
