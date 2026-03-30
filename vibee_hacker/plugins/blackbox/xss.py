# vibee_hacker/plugins/blackbox/xss.py
"""Reflected XSS detection plugin."""

from __future__ import annotations

import shlex
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

XSS_PAYLOADS = [
    "<script>alert('vbh')</script>",
    "<img src=x onerror=alert('vbh')>",
    "'\"><svg/onload=alert('vbh')>",
]


class XssPlugin(PluginBase):
    name = "xss"
    description = "Reflected XSS detection"
    category = "blackbox"
    phase = 3
    base_severity = Severity.HIGH
    detection_criteria = "Injected XSS payload reflected unescaped in response body"
    expected_evidence = "XSS payload string found verbatim in response"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        parsed = urlparse(target.url)
        params = parse_qs(parsed.query)
        if not params:
            return []

        results = []
        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            for param_name in params:
                for payload in XSS_PAYLOADS:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param_name] = payload
                    test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

                    try:
                        resp = await client.get(test_url)
                    except httpx.HTTPError:
                        continue

                    content_type = resp.headers.get("content-type", "")
                    if "text/html" not in content_type:
                        continue

                    if payload in resp.text:
                        results.append(Result(
                            plugin_name=self.name,
                            base_severity=self.base_severity,
                            title=f"Reflected XSS in parameter '{param_name}'",
                            description=f"Payload reflected unescaped: {payload[:50]}",
                            evidence=payload,
                            cwe_id="CWE-79",
                            endpoint=target.url,
                            param_name=param_name,
                            curl_command=f"curl {shlex.quote(test_url)}",
                            rule_id="xss_reflected",
                        ))
                        return results

        return results
