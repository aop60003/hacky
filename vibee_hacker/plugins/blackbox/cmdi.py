# vibee_hacker/plugins/blackbox/cmdi.py
"""OS Command Injection detection plugin."""

from __future__ import annotations

import shlex
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

MARKER = "VIBEE_CMD_MARKER"
PAYLOADS = [
    f";echo {MARKER}",
    f"|echo {MARKER}",
    f"`echo {MARKER}`",
    f"$(echo {MARKER})",
    f"&&echo {MARKER}",
    f"& echo {MARKER}",        # Windows cmd
]


class CmdiPlugin(PluginBase):
    name = "cmdi"
    description = "OS Command Injection detection"
    category = "blackbox"
    phase = 3
    base_severity = Severity.CRITICAL
    detection_criteria = "Command output marker found in response after injecting shell commands"
    expected_evidence = "VIBEE_CMD_MARKER string in response body"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        parsed = urlparse(target.url)
        params = parse_qs(parsed.query)
        if not params:
            return []

        MAX_PARAMS = 10
        if len(params) > MAX_PARAMS:
            params = dict(list(params.items())[:MAX_PARAMS])

        results = []
        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            # Fetch baseline response and abort if MARKER already present
            try:
                baseline_resp = await client.get(target.url)
                if MARKER in baseline_resp.text:
                    return []
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

            for param_name, values in params.items():
                original = values[0] if values else ""
                for payload in PAYLOADS:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param_name] = original + payload
                    test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

                    try:
                        resp = await client.get(test_url)
                    except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                        continue

                    if len(resp.text) > 1_000_000:  # 1MB max response
                        continue

                    if MARKER in resp.text:
                        results.append(Result(
                            plugin_name=self.name,
                            base_severity=self.base_severity,
                            title=f"Command Injection in parameter '{param_name}'",
                            description=f"Output-based CMDi with payload: {payload}",
                            evidence=MARKER,
                            cwe_id="CWE-78",
                            endpoint=target.url,
                            param_name=param_name,
                            curl_command=f"curl {shlex.quote(test_url)}",
                            rule_id="cmdi_output_based",
                        ))
                        return results

        return results
