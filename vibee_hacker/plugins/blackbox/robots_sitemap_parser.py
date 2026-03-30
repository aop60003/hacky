# vibee_hacker/plugins/blackbox/robots_sitemap_parser.py
"""Robots.txt and Sitemap.xml parser plugin."""

from __future__ import annotations

import re
import shlex
from urllib.parse import urljoin, urlparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

DISALLOW_RE = re.compile(r"^Disallow:\s*(.+)$", re.MULTILINE | re.IGNORECASE)
SITEMAP_URL_RE = re.compile(r"<loc>\s*(https?://[^\s<]+)\s*</loc>", re.IGNORECASE)


def _base_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


class RobotsSitemapPlugin(PluginBase):
    name = "robots_sitemap_parser"
    description = "Parse robots.txt and sitemap.xml for sensitive paths"
    category = "blackbox"
    phase = 1
    base_severity = Severity.INFO
    detection_criteria = "Disallow paths in robots.txt revealing sensitive endpoints"
    expected_evidence = "Disallow path from robots.txt"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        base = _base_url(target.url)
        results: list[Result] = []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            # --- robots.txt ---
            robots_url = urljoin(base + "/", "robots.txt")
            try:
                resp = await client.get(robots_url)
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

            if resp.status_code == 200 and len(resp.text) <= 1_000_000:
                disallowed = DISALLOW_RE.findall(resp.text)
                for path in disallowed:
                    path = path.strip()
                    if not path or path == "/":
                        continue
                    results.append(Result(
                        plugin_name=self.name,
                        base_severity=self.base_severity,
                        title=f"Sensitive path in robots.txt: {path}",
                        description=(
                            f"robots.txt Disallow directive reveals a potentially sensitive path: {path}"
                        ),
                        evidence=f"Disallow: {path}",
                        cwe_id=None,
                        endpoint=robots_url,
                        curl_command=f"curl {shlex.quote(robots_url)}",
                        rule_id="robots_sensitive_path",
                    ))

            # --- sitemap.xml ---
            sitemap_url = urljoin(base + "/", "sitemap.xml")
            try:
                sitemap_resp = await client.get(sitemap_url)
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return results

            if sitemap_resp.status_code == 200 and len(sitemap_resp.text) <= 1_000_000:
                urls = SITEMAP_URL_RE.findall(sitemap_resp.text)
                for url in urls[:50]:  # cap at 50
                    results.append(Result(
                        plugin_name=self.name,
                        base_severity=self.base_severity,
                        title=f"Sitemap URL discovered: {url}",
                        description=f"URL discovered via sitemap.xml: {url}",
                        evidence=f"<loc>{url}</loc>",
                        cwe_id=None,
                        endpoint=sitemap_url,
                        curl_command=f"curl {shlex.quote(sitemap_url)}",
                        rule_id="robots_sensitive_path",
                    ))

        return results
