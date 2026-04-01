# vibee_hacker/plugins/blackbox/open_redirect.py
"""Open redirect detection plugin."""

from __future__ import annotations

import shlex
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

REDIRECT_PARAMS = ["url", "redirect", "next", "return", "goto", "dest", "redir"]
EVIL_URL = "https://evil.com"


class OpenRedirectPlugin(PluginBase):
    name = "open_redirect"
    description = "Detect open redirect vulnerabilities via redirect parameter injection"
    category = "blackbox"
    phase = 3
    base_severity = Severity.MEDIUM
    detection_criteria = "3xx redirect with Location pointing to evil.com after payload injection"
    expected_evidence = "Location header containing evil.com in 3xx response"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        # Build list of URLs to test: start URL + crawled URLs
        urls_to_test: list[str] = [target.url]
        if context:
            for crawled_url in (context.crawl_urls or [])[:20]:
                if crawled_url != target.url:
                    urls_to_test.append(crawled_url)

        results: list[Result] = []

        async with httpx.AsyncClient(
            verify=target.verify_ssl,
            timeout=10,
            follow_redirects=False,
        ) as client:
            for test_target_url in urls_to_test:
                parsed = urlparse(test_target_url)
                params = parse_qs(parsed.query)

                # Find redirect-related parameters
                redirect_params = [p for p in params if p.lower() in REDIRECT_PARAMS]
                if not redirect_params:
                    continue

                for param in redirect_params:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param] = EVIL_URL
                    test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

                    try:
                        resp = await client.get(test_url)
                    except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                        continue

                    if resp.status_code in (301, 302, 303, 307, 308):
                        location = resp.headers.get("location", "")
                        if "evil.com" in location:
                            results.append(Result(
                                plugin_name=self.name,
                                base_severity=self.base_severity,
                                title=f"Open redirect via parameter '{param}'",
                                description=(
                                    f"Parameter '{param}' causes an unvalidated redirect to {location}."
                                ),
                                evidence=f"Status: {resp.status_code} | Location: {location}",
                                cwe_id="CWE-601",
                                endpoint=test_url,
                                param_name=param,
                                curl_command=f"curl -v {shlex.quote(test_url)}",
                                rule_id="open_redirect",
                            ))
                            return results

        return results
