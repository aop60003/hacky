# vibee_hacker/plugins/blackbox/cloud_creds_leak.py
"""Cloud credentials leak detection plugin."""

from __future__ import annotations

import re
import shlex
from html.parser import HTMLParser
from urllib.parse import urljoin

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

CRED_PATTERNS = [
    (
        re.compile(r"AKIA[0-9A-Z]{16}"),
        "aws",
        "AWS Access Key ID",
    ),
    (
        re.compile(r"AIza[0-9A-Za-z_-]{35}"),
        "gcp",
        "GCP API Key",
    ),
    (
        re.compile(r"ghp_[0-9a-zA-Z]{36}"),
        "github",
        "GitHub Personal Access Token",
    ),
    (
        re.compile(r"xox[bprs]-[0-9a-zA-Z-]+"),
        "slack",
        "Slack Token",
    ),
]


class _ScriptSrcParser(HTMLParser):
    """Extract src attributes from <script> tags."""

    def __init__(self) -> None:
        super().__init__()
        self.js_urls: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "script":
            for name, value in attrs:
                if name.lower() == "src" and value:
                    self.js_urls.append(value)


def _scan_text(text: str) -> list[tuple[str, str, str]]:
    """Return list of (pattern_id, label, matched_value) found in text."""
    findings = []
    for pattern, pattern_id, label in CRED_PATTERNS:
        match = pattern.search(text)
        if match:
            findings.append((pattern_id, label, match.group(0)))
    return findings


class CloudCredsPlugin(PluginBase):
    name = "cloud_creds_leak"
    description = "Detect cloud provider credentials leaked in responses and JS files"
    category = "blackbox"
    phase = 2
    base_severity = Severity.CRITICAL
    detection_criteria = "Cloud credential patterns (AWS, GCP, GitHub, Slack) in response or JS"
    expected_evidence = "Matched credential pattern in HTTP response or linked JS file"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        results: list[Result] = []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            # Fetch main page
            try:
                resp = await client.get(target.url)
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

            if len(resp.text) > 1_000_000:
                return []

            # Scan main page body
            for pattern_id, label, matched in _scan_text(resp.text):
                results.append(Result(
                    plugin_name=self.name,
                    base_severity=self.base_severity,
                    title=f"Cloud credential leaked: {label}",
                    description=f"{label} found in HTTP response body at {target.url}.",
                    evidence=f"Matched value starts with: {matched[:8]}...",
                    cwe_id="CWE-798",
                    endpoint=target.url,
                    curl_command=f"curl {shlex.quote(target.url)}",
                    rule_id=f"cloud_creds_{pattern_id}",
                ))

            if results:
                return results

            # Parse JS links from main page and scan those too
            parser = _ScriptSrcParser()
            try:
                parser.feed(resp.text)
            except Exception:
                pass

            for js_src in parser.js_urls[:10]:  # cap at 10 JS files
                js_url = urljoin(target.url, js_src)
                try:
                    js_resp = await client.get(js_url)
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                if len(js_resp.text) > 1_000_000:
                    continue

                for pattern_id, label, matched in _scan_text(js_resp.text):
                    results.append(Result(
                        plugin_name=self.name,
                        base_severity=self.base_severity,
                        title=f"Cloud credential leaked in JS: {label}",
                        description=f"{label} found in linked JS file: {js_url}.",
                        evidence=f"Matched value starts with: {matched[:8]}...",
                        cwe_id="CWE-798",
                        endpoint=js_url,
                        curl_command=f"curl {shlex.quote(js_url)}",
                        rule_id=f"cloud_creds_{pattern_id}",
                    ))

        return results
