# vibee_hacker/plugins/blackbox/waf_bypass.py
"""WAF bypass detection plugin using encoded payload variants."""

from __future__ import annotations

import shlex
from urllib.parse import quote

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

# Encoded bypass payloads to try when a WAF is detected
BYPASS_PAYLOADS = [
    # Double URL encoded <script>
    "%253Cscript%253Ealert(1)%253C%2Fscript%253E",
    # Case alternation
    "<scrIPt>alert(1)</scrIPt>",
    # Self-closing tag
    "<script/x>alert(1)</script>",
    # Unicode escape
    "\u003cscript\u003ealert(1)\u003c/script\u003e",
    # HTML entity
    "&lt;script&gt;alert(1)&lt;/script&gt;",
]

BLOCK_INDICATORS = [403, 406, 429, 503]


class WafBypassPlugin(PluginBase):
    name = "waf_bypass"
    description = "Attempt WAF bypass using encoded/obfuscated payloads when WAF is detected"
    category = "blackbox"
    phase = 3
    base_severity = Severity.HIGH
    detection_criteria = "Encoded payload not blocked (non-403 response) when WAF is present"
    expected_evidence = "Encoded XSS payload returned 200 instead of being blocked by WAF"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        # Only run if WAF was detected
        if context is None or not context.waf_info:
            return []

        waf_name = context.waf_info.get("waf_name", "Unknown WAF")
        results: list[Result] = []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            for payload in BYPASS_PAYLOADS:
                probe_url = target.url.rstrip("/") + "/?waf_bypass=" + payload
                try:
                    resp = await client.get(probe_url)
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                if resp.status_code not in BLOCK_INDICATORS:
                    results.append(Result(
                        plugin_name=self.name,
                        base_severity=self.base_severity,
                        title=f"WAF bypass possible: encoded payload not blocked by {waf_name}",
                        description=(
                            f"The WAF '{waf_name}' did not block an encoded XSS payload. "
                            f"The payload '{payload}' received a {resp.status_code} response "
                            f"instead of being blocked. This suggests the WAF can be bypassed "
                            f"using encoding techniques."
                        ),
                        evidence=(
                            f"Payload: {payload} | Status: {resp.status_code} | "
                            f"WAF: {waf_name}"
                        ),
                        recommendation=(
                            "Update WAF rules to detect encoded and obfuscated payloads. "
                            "Enable decode-before-inspect features in your WAF configuration."
                        ),
                        cwe_id="CWE-693",
                        endpoint=probe_url,
                        curl_command=f"curl {shlex.quote(probe_url)}",
                        rule_id="waf_bypass_possible",
                    ))
                    return results  # Return on first bypass found

        return results
