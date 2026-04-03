# vibee_hacker/plugins/blackbox/hpp.py
"""HTTP Parameter Pollution (HPP) detection plugin."""

from __future__ import annotations

import shlex
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

# Marker values to detect which copy of a duplicated param the server uses
MARKER_A = "hpp_val_a"
MARKER_B = "hpp_val_b"
MAX_PARAMS = 10


class HppPlugin(PluginBase):
    name = "hpp"
    description = "HTTP Parameter Pollution — duplicate params to detect inconsistent server-side handling"
    category = "blackbox"
    phase = 3
    base_severity = Severity.MEDIUM
    destructive_level = 1
    detection_criteria = (
        "Server returns both marker values or the second marker value when params are duplicated, "
        "indicating it processes multiple values without sanitisation"
    )
    expected_evidence = "Response reflects MARKER_B (second param) or concatenation of both markers"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        urls_to_test: list[str] = [target.url]
        if context:
            for crawled_url in (context.crawl_urls or [])[:10]:
                if crawled_url != target.url and "?" in crawled_url:
                    urls_to_test.append(crawled_url)

        results: list[Result] = []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            for test_url in urls_to_test:
                parsed = urlparse(test_url)
                params = parse_qs(parsed.query)
                if not params:
                    continue

                capped = dict(list(params.items())[:MAX_PARAMS])

                for param_name in capped:
                    # Build query string with duplicate param: param=MARKER_A&param=MARKER_B
                    other_params = {k: v[0] for k, v in capped.items() if k != param_name}
                    base_qs = urlencode(other_params)
                    dup_qs = f"{param_name}={MARKER_A}&{param_name}={MARKER_B}"
                    raw_query = (base_qs + "&" + dup_qs) if base_qs else dup_qs
                    polluted_url = urlunparse(parsed._replace(query=raw_query))

                    try:
                        resp = await client.get(polluted_url)
                    except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                        continue

                    if len(resp.text) > 1_000_000:
                        continue

                    body = resp.text
                    # Vulnerable if the server echoes MARKER_B (uses last value) or both markers
                    if MARKER_B in body or (MARKER_A in body and MARKER_B in body):
                        results.append(Result(
                            plugin_name=self.name,
                            base_severity=self.base_severity,
                            title=f"HTTP Parameter Pollution in parameter '{param_name}'",
                            description=(
                                f"The server processes duplicate values for parameter '{param_name}'. "
                                f"Sending '{param_name}={MARKER_A}&{param_name}={MARKER_B}' caused "
                                f"one or both marker values to appear in the response, indicating "
                                f"inconsistent multi-value handling that may be exploited to bypass "
                                f"filters or access controls."
                            ),
                            evidence=(
                                f"Duplicate param '{param_name}' with values "
                                f"'{MARKER_A}' and '{MARKER_B}' — "
                                f"marker(s) reflected in response body | Status: {resp.status_code}"
                            ),
                            cwe_id="CWE-235",
                            endpoint=test_url,
                            param_name=param_name,
                            curl_command=f"curl {shlex.quote(polluted_url)}",
                            rule_id="hpp_duplicate_param",
                        ))
                        return results

        return results
