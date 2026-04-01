# vibee_hacker/plugins/blackbox/api_key_exposure.py
"""API key exposure detection plugin (P2-3)."""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

API_KEY_PATTERNS: list[tuple[str, str]] = [
    (
        r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
        "generic_api_key",
    ),
    (
        r'(?:secret[_-]?key|secretkey)\s*[=:]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
        "secret_key",
    ),
    (
        r'(?:access[_-]?token)\s*[=:]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
        "access_token",
    ),
    (
        r'(?:client[_-]?secret)\s*[=:]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
        "client_secret",
    ),
    (r"sk_live_[a-zA-Z0-9]{24,}", "stripe_secret_key"),
    (r"sq0csp-[a-zA-Z0-9_-]{43}", "square_access_token"),
    (r"xox[bprs]-[a-zA-Z0-9-]+", "slack_token"),
]

_COMPILED_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(pattern, re.IGNORECASE), key_type)
    for pattern, key_type in API_KEY_PATTERNS
]

_JS_SCRIPT_RE = re.compile(
    r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE
)

MAX_JS_FILES = 10


def _scan_text(text: str) -> list[tuple[str, str]]:
    """Return list of (key_type, matched_value) for all pattern hits.

    Uses group(1) as the value for patterns with a capture group, but
    group(0) (the full match) as the deduplication key so that the same
    raw token is never emitted twice regardless of which group is used.
    """
    hits: list[tuple[str, str]] = []
    seen_full: set[str] = set()
    for compiled, key_type in _COMPILED_PATTERNS:
        for m in compiled.finditer(text):
            full_match = m.group(0)
            if full_match in seen_full:
                continue
            seen_full.add(full_match)
            # Expose the captured value (group 1) when available, else full match
            value = m.group(1) if m.lastindex else full_match
            hits.append((key_type, value))
    return hits


def _same_domain(base_url: str, link: str) -> bool:
    """Return True if link resolves to the same domain as base_url."""
    try:
        resolved = urljoin(base_url, link)
        base_host = urlparse(base_url).hostname
        link_host = urlparse(resolved).hostname
        return base_host == link_host
    except Exception:
        return False


class ApiKeyExposurePlugin(PluginBase):
    name = "api_key_exposure"
    description = "Scan target page and linked JS files for exposed API keys/secrets"
    category = "blackbox"
    phase = 2
    base_severity = Severity.CRITICAL
    detection_criteria = "API key pattern matched in HTTP response body or linked JS file"
    destructive_level = 0

    def is_applicable(self, target: Target) -> bool:
        return bool(target.url)

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        results: list[Result] = []
        seen_keys: set[tuple[str, str]] = set()

        async with httpx.AsyncClient(
            verify=target.verify_ssl,
            timeout=10,
            follow_redirects=True,
        ) as client:
            # Fetch the main page
            try:
                resp = await client.get(target.url)
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

            main_body = resp.text

            # Scan main page
            for key_type, value in _scan_text(main_body):
                dedup_key = (key_type, value)
                if dedup_key in seen_keys:
                    continue
                seen_keys.add(dedup_key)
                results.append(self._make_result(
                    key_type=key_type,
                    value=value,
                    source_url=target.url,
                    endpoint=target.url,
                ))

            # Collect same-domain JS files from <script src="...">
            js_urls: list[str] = []
            for m in _JS_SCRIPT_RE.finditer(main_body):
                src = m.group(1)
                if _same_domain(target.url, src):
                    full_url = urljoin(target.url, src)
                    if full_url not in js_urls:
                        js_urls.append(full_url)
                if len(js_urls) >= MAX_JS_FILES:
                    break

            # Scan each JS file
            for js_url in js_urls:
                try:
                    js_resp = await client.get(js_url)
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                js_body = js_resp.text
                for key_type, value in _scan_text(js_body):
                    dedup_key = (key_type, value)
                    if dedup_key in seen_keys:
                        continue
                    seen_keys.add(dedup_key)
                    results.append(self._make_result(
                        key_type=key_type,
                        value=value,
                        source_url=js_url,
                        endpoint=js_url,
                    ))

        return results

    @staticmethod
    def _make_result(
        key_type: str,
        value: str,
        source_url: str,
        endpoint: str,
    ) -> Result:
        masked = value[:4] + "***" + value[-2:] if len(value) > 8 else value[:4] + "***"
        return Result(
            plugin_name="api_key_exposure",
            base_severity=Severity.CRITICAL,
            title=f"Exposed API key: {key_type}",
            description=(
                f"An API key or secret of type '{key_type}' was found in the response "
                f"from {source_url}. Exposed keys can be exploited by attackers to "
                "access third-party services or internal APIs."
            ),
            recommendation=(
                "Remove the key from client-side code immediately. Rotate the key and "
                "store secrets server-side or in a secrets management service."
            ),
            cwe_id="CWE-798",
            evidence=f"{key_type}: {masked}",
            endpoint=endpoint,
            rule_id=f"api_key_exposed_{key_type}",
        )
