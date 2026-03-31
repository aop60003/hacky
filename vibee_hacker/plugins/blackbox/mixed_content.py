# vibee_hacker/plugins/blackbox/mixed_content.py
"""Mixed content detection plugin."""

from __future__ import annotations

import re
from urllib.parse import urlparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

# Active mixed content: loaded and executed (HIGH risk)
ACTIVE_TAGS = {
    "script": "src",
    "iframe": "src",
    "link": "href",
    "object": "data",
    "embed": "src",
}

# Passive mixed content: displayed but not executed (MEDIUM risk)
PASSIVE_TAGS = {
    "img": "src",
    "audio": "src",
    "video": "src",
    "source": "src",
}

# Generic pattern to find http:// URLs in tag attributes
HTTP_ATTR_RE = re.compile(
    r'<(script|iframe|link|object|embed|img|audio|video|source)[^>]+(?:src|href|data)=["\']?(http://[^\s"\'>\)]+)',
    re.I | re.S,
)


class MixedContentPlugin(PluginBase):
    name = "mixed_content"
    description = "Detect mixed content (HTTP resources loaded on HTTPS pages)"
    category = "blackbox"
    phase = 2
    base_severity = Severity.MEDIUM
    detection_criteria = "HTTPS page loads resources via http://"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        # Only applicable to HTTPS targets
        parsed = urlparse(target.url)
        if parsed.scheme != "https":
            return []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            try:
                resp = await client.get(target.url)
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

        content_type = resp.headers.get("content-type", "")
        if "html" not in content_type.lower() and not resp.text.lstrip().startswith("<"):
            return []

        results: list[Result] = []
        seen_urls: set[str] = set()

        try:
            body = resp.text[:200_000]
        except Exception:
            return []

        for match in HTTP_ATTR_RE.finditer(body):
            tag_name = match.group(1).lower()
            http_url = match.group(2)

            if http_url in seen_urls:
                continue
            seen_urls.add(http_url)

            is_active = tag_name in ACTIVE_TAGS
            severity = Severity.HIGH if is_active else Severity.MEDIUM
            content_type_label = "active" if is_active else "passive"

            results.append(Result(
                plugin_name=self.name,
                base_severity=severity,
                title=f"Mixed content: {content_type_label} HTTP resource on HTTPS page",
                description=(
                    f"The HTTPS page loads a {content_type_label} resource ({tag_name} tag) over HTTP: {http_url}. "
                    "This allows a network attacker to intercept or modify the resource."
                ),
                recommendation=(
                    f"Change the resource URL to use HTTPS: {http_url.replace('http://', 'https://', 1)}"
                ),
                evidence=f"<{tag_name}> tag with HTTP src/href: {http_url}",
                cwe_id="CWE-319",
                endpoint=target.url,
                rule_id=f"mixed_content_{content_type_label}",
            ))

        return results
