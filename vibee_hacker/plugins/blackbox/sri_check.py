# vibee_hacker/plugins/blackbox/sri_check.py
"""Subresource Integrity (SRI) check plugin."""

from __future__ import annotations

import re
from urllib.parse import urlparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

# Match <script src="..."> and <link href="..."> tags (single-line friendly)
EXTERNAL_RESOURCE_RE = re.compile(
    r'<(script|link)\b([^>]*?)>',
    re.I | re.S,
)

SRC_HREF_RE = re.compile(r'(?:src|href)=["\']([^"\']+)["\']', re.I)
INTEGRITY_RE = re.compile(r'\bintegrity=["\'][^"\']+["\']', re.I)


def _is_external(url: str, page_host: str) -> bool:
    """Return True if the URL is from a different origin than the page."""
    if url.startswith("//"):
        return True
    parsed = urlparse(url)
    if not parsed.scheme:
        return False  # relative URL
    return parsed.hostname != page_host if parsed.hostname else False


class SriCheckPlugin(PluginBase):
    name = "sri_check"
    description = "Check external scripts and stylesheets for missing Subresource Integrity (SRI) attributes"
    category = "blackbox"
    phase = 2
    base_severity = Severity.MEDIUM
    detection_criteria = "External <script> or <link> tag lacks an integrity attribute"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            try:
                resp = await client.get(target.url)
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

        try:
            body = resp.text[:200_000]
        except Exception:
            return []

        page_host = urlparse(target.url).hostname or ""
        results: list[Result] = []
        seen_urls: set[str] = set()

        for match in EXTERNAL_RESOURCE_RE.finditer(body):
            tag_name = match.group(1).lower()
            attrs = match.group(2)

            src_match = SRC_HREF_RE.search(attrs)
            if not src_match:
                continue

            resource_url = src_match.group(1)
            if resource_url in seen_urls:
                continue

            if not _is_external(resource_url, page_host):
                continue

            seen_urls.add(resource_url)

            has_integrity = bool(INTEGRITY_RE.search(attrs))
            if has_integrity:
                continue

            results.append(Result(
                plugin_name=self.name,
                base_severity=self.base_severity,
                title=f"Missing SRI integrity attribute on external <{tag_name}>",
                description=(
                    f"The external <{tag_name}> resource '{resource_url}' does not have a Subresource Integrity "
                    "attribute. If the CDN or host is compromised, malicious code could be injected."
                ),
                recommendation=(
                    f"Add an integrity attribute with the SHA-384 hash of the resource, e.g.:\n"
                    f'<{tag_name} src="{resource_url}" integrity="sha384-..." crossorigin="anonymous">'
                ),
                evidence=f'<{tag_name}> without integrity: {resource_url}',
                cwe_id="CWE-353",
                endpoint=target.url,
                rule_id="sri_missing",
            ))

        return results
