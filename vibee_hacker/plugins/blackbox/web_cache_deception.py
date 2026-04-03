# vibee_hacker/plugins/blackbox/web_cache_deception.py
"""Web Cache Deception detection plugin."""

from __future__ import annotations

import shlex
from urllib.parse import urlparse, urljoin

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

# Static file extensions that caches commonly store without revalidation
DECOY_SUFFIXES = [
    "/nonexistent.css",
    "/nonexistent.js",
    "/nonexistent.png",
]

# Response headers that reveal a cache HIT
CACHE_HIT_HEADERS = {
    "x-cache": ["hit"],
    "cf-cache-status": ["hit"],
    "x-drupal-cache": ["hit"],
    "x-varnish-cache": ["hit"],
    "age": None,  # Any non-zero Age header indicates caching
}


def _is_cache_hit(headers: dict[str, str]) -> bool:
    for header, values in CACHE_HIT_HEADERS.items():
        header_val = headers.get(header, "").lower().strip()
        if not header_val:
            continue
        if values is None:
            # Age header — any non-zero positive integer means cached
            try:
                if int(header_val) > 0:
                    return True
            except ValueError:
                pass
        else:
            if any(v in header_val for v in values):
                return True
    return False


class WebCacheDeceptionPlugin(PluginBase):
    name = "web_cache_deception"
    description = (
        "Web Cache Deception — append static-extension suffix to authenticated URLs "
        "and check if sensitive content is served from cache"
    )
    category = "blackbox"
    phase = 3
    base_severity = Severity.HIGH
    destructive_level = 0
    detection_criteria = (
        "Decorated URL (e.g. /profile/nonexistent.css) returns the same content "
        "as the original URL AND a cache HIT header is present"
    )
    expected_evidence = "Cache HIT header observed on decorated URL that serves dynamic content"

    def is_applicable(self, target: Target) -> bool:
        return bool(target.url)

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        parsed = urlparse(target.url)
        # Strip trailing slash for clean suffix appending
        base_path = parsed.path.rstrip("/") or "/"

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10, follow_redirects=True) as client:
            # Fetch baseline
            try:
                baseline_resp = await client.get(target.url)
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

            if baseline_resp.status_code not in (200, 403):
                return []

            baseline_text = baseline_resp.text[:5000]  # Compare first 5 KB

            for suffix in DECOY_SUFFIXES:
                decorated_path = base_path + suffix
                decorated_url = parsed._replace(path=decorated_path).geturl()

                try:
                    resp = await client.get(decorated_url)
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                if resp.status_code != 200:
                    continue

                if len(resp.text) > 1_000_000:
                    continue

                resp_headers = {k.lower(): v for k, v in resp.headers.items()}

                # Check for cache HIT
                if not _is_cache_hit(resp_headers):
                    continue

                # Check content similarity: any non-trivial overlap with baseline
                # or that the response has real content (not just a static 404 page)
                snippet_len = min(50, len(baseline_text))
                snippet_match = (
                    snippet_len > 10 and baseline_text[:snippet_len] in resp.text
                )

                if snippet_match or len(resp.text) > 50:
                    return [Result(
                        plugin_name=self.name,
                        base_severity=self.base_severity,
                        title=f"Web Cache Deception risk at '{decorated_path}'",
                        description=(
                            f"Appending '{suffix}' to the URL caused the server to return "
                            f"content (possibly authenticated/sensitive) with a cache HIT header. "
                            f"An attacker can trick a victim into visiting the decorated URL and "
                            f"then retrieve the cached sensitive response without authentication."
                        ),
                        evidence=(
                            f"Cache HIT on decorated URL '{decorated_path}' | "
                            f"Status: {resp.status_code} | "
                            f"Cache header: {next((f'{k}: {v}' for k, v in resp_headers.items() if k in CACHE_HIT_HEADERS), 'unknown')}"
                        ),
                        cwe_id="CWE-525",
                        endpoint=decorated_url,
                        curl_command=f"curl -I {shlex.quote(decorated_url)}",
                        rule_id="web_cache_deception",
                    )]

        return []
