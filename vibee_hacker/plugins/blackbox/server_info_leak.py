# vibee_hacker/plugins/blackbox/server_info_leak.py
"""Server information leakage detection plugin."""

from __future__ import annotations

import re

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

# Headers that may disclose server/technology version info
LEAKY_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Drupal-Cache",
    "X-Runtime",
    "X-Version",
]

# Regex to detect version-like strings (e.g. Apache/2.4.51, PHP/8.1.0)
VERSION_RE = re.compile(r"[\d]+\.[\d]+", re.I)

# HTML comment patterns that suggest version/build disclosure
HTML_COMMENT_RE = re.compile(r"<!--.*?(?:version|build|release|rev)\s*[\d]", re.I)


class ServerInfoLeakPlugin(PluginBase):
    name = "server_info_leak"
    description = "Detect server/technology version information leakage via response headers and HTML comments"
    category = "blackbox"
    phase = 2
    base_severity = Severity.LOW
    detection_criteria = "Response headers or HTML body reveals server software version or technology stack"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            try:
                resp = await client.get(target.url)
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

        results: list[Result] = []
        resp_headers = {k.lower(): v for k, v in resp.headers.items()}

        for header in LEAKY_HEADERS:
            value = resp_headers.get(header.lower(), "")
            if not value:
                continue
            # Report if the header value contains a version number or is non-generic
            if VERSION_RE.search(value) or "/" in value or header.lower() != "server":
                results.append(Result(
                    plugin_name=self.name,
                    base_severity=self.base_severity,
                    title=f"Server information disclosure via {header} header",
                    description=(
                        f"The {header} response header discloses server/technology information: '{value}'. "
                        "This helps attackers identify vulnerable software versions."
                    ),
                    recommendation=(
                        f"Remove or genericise the {header} header. "
                        "Do not include version numbers in HTTP response headers."
                    ),
                    evidence=f"{header}: {value}",
                    cwe_id="CWE-200",
                    endpoint=target.url,
                    rule_id="server_info_header_leak",
                ))
                break  # One finding is sufficient; avoid noise

        # Check HTML body for version-disclosing comments (only if no header finding)
        if not results:
            try:
                body = resp.text[:50_000]  # Limit to first 50 KB
            except Exception:
                body = ""

            match = HTML_COMMENT_RE.search(body)
            if match:
                results.append(Result(
                    plugin_name=self.name,
                    base_severity=self.base_severity,
                    title="Server information disclosure via HTML comment",
                    description=(
                        "The HTML response contains a comment that discloses version/build information. "
                        "Attackers can use this to identify vulnerable software versions."
                    ),
                    recommendation="Remove version/build information from HTML comments in production responses.",
                    evidence=f"HTML comment: {match.group(0)[:120]}",
                    cwe_id="CWE-200",
                    endpoint=target.url,
                    rule_id="server_info_html_comment_leak",
                ))

        return results
