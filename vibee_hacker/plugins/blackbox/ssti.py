# vibee_hacker/plugins/blackbox/ssti.py
"""Server-Side Template Injection (SSTI) detection plugin."""

from __future__ import annotations

import shlex
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

# Math expression payloads — rendered result is 49 (7*7)
PAYLOADS = [
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "#{7*7}",
    "{7*7}",
]

EXPECTED_RESULT = "49"

MAX_PARAMS = 10


class SstiPlugin(PluginBase):
    name = "ssti"
    description = "Server-Side Template Injection detection (math reflection)"
    category = "blackbox"
    phase = 3
    base_severity = Severity.CRITICAL
    detection_criteria = "Math expression payload reflected as computed result in response"
    expected_evidence = "Response contains '49' after injecting template expression '{{7*7}}'"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        parsed = urlparse(target.url)
        params = parse_qs(parsed.query)
        if not params:
            return []

        if len(params) > MAX_PARAMS:
            params = dict(list(params.items())[:MAX_PARAMS])

        results = []
        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            # Fetch baseline to check if 49 is already present
            try:
                baseline_resp = await client.get(target.url)
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

            baseline_has_result = EXPECTED_RESULT in baseline_resp.text

            for param_name, values in params.items():
                original_value = values[0] if values else ""
                for payload in PAYLOADS:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param_name] = original_value + payload
                    test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

                    try:
                        resp = await client.get(test_url)
                    except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                        continue

                    if len(resp.text) > 1_000_000:  # 1 MB max response
                        continue

                    if EXPECTED_RESULT in resp.text and not baseline_has_result:
                        results.append(Result(
                            plugin_name=self.name,
                            base_severity=self.base_severity,
                            title=f"Server-Side Template Injection in parameter '{param_name}'",
                            description=(
                                f"SSTI detected: payload {payload!r} was evaluated "
                                f"and the result '{EXPECTED_RESULT}' appeared in the response."
                            ),
                            evidence=f"payload={payload!r} → response contains '{EXPECTED_RESULT}'",
                            cwe_id="CWE-1336",
                            endpoint=target.url,
                            param_name=param_name,
                            curl_command=f"curl {shlex.quote(test_url)}",
                            rule_id="ssti_math_reflection",
                        ))
                        return results  # Stop on first confirmed finding

        return results
