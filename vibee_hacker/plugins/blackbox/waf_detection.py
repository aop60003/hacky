# vibee_hacker/plugins/blackbox/waf_detection.py
"""WAF Detection plugin."""

from __future__ import annotations

import shlex

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

PAYLOADS = [
    "<script>alert(1)</script>",
    "' OR 1=1--",
]

WAF_SIGNATURES = [
    # (header_name, header_value_pattern, waf_name)
    ("cf-ray", None, "Cloudflare"),
    ("x-amzn-waf", None, "AWS WAF"),
    ("x-amzn-requestid", None, "AWS WAF"),
]

WAF_BODY_PATTERNS = [
    ("Mod_Security", "ModSecurity"),
    ("modsecurity", "ModSecurity"),
    ("Request Rejected", "Generic WAF"),
    ("Access Denied", "Generic WAF"),
    ("Forbidden by", "Generic WAF"),
    ("blocked by", "Generic WAF"),
]


def _detect_waf(resp: httpx.Response) -> str | None:
    """Return WAF name if detected, else None."""
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}

    for header, _, waf_name in WAF_SIGNATURES:
        if header.lower() in headers_lower:
            return waf_name

    if resp.status_code == 403:
        body = resp.text
        for pattern, waf_name in WAF_BODY_PATTERNS:
            if pattern.lower() in body.lower():
                return waf_name
        return "Generic WAF (403)"

    body = resp.text
    for pattern, waf_name in WAF_BODY_PATTERNS:
        if pattern.lower() in body.lower():
            return waf_name

    return None


class WafDetectionPlugin(PluginBase):
    name = "waf_detection"
    description = "WAF Detection via malicious payload probing"
    category = "blackbox"
    phase = 1
    base_severity = Severity.INFO
    detection_criteria = "WAF signatures in response headers, status codes, or body"
    expected_evidence = "WAF header (cf-ray, x-amzn-waf) or block page pattern"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10, follow_redirects=False) as client:
            for payload in PAYLOADS:
                probe_url = target.url.rstrip("/") + "/?waf_probe=" + payload
                try:
                    resp = await client.get(probe_url)
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    return []

                if len(resp.text) > 1_000_000:
                    continue

                waf_name = _detect_waf(resp)
                if waf_name:
                    if context is not None:
                        context.waf_info = {
                            "waf_name": waf_name,
                            "detected_by": "payload_probe",
                            "probe_url": probe_url,
                            "status_code": resp.status_code,
                        }
                    return [Result(
                        plugin_name=self.name,
                        base_severity=self.base_severity,
                        title=f"WAF Detected: {waf_name}",
                        description=(
                            f"A Web Application Firewall ({waf_name}) was detected. "
                            f"Probe URL returned status {resp.status_code}."
                        ),
                        evidence=f"WAF: {waf_name} | Status: {resp.status_code} | Headers: {dict(resp.headers)}",
                        cwe_id=None,
                        endpoint=probe_url,
                        curl_command=f"curl {shlex.quote(probe_url)}",
                        rule_id="waf_detected",
                    )]

        return []
