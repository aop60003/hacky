"""Technology fingerprinting plugin — identifies server/framework from HTTP responses."""

from __future__ import annotations

import re

import httpx

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

# (label, pattern) — applied to Server header value
_SERVER_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("Apache", re.compile(r"Apache", re.I)),
    ("Nginx", re.compile(r"nginx", re.I)),
    ("IIS", re.compile(r"Microsoft-IIS", re.I)),
    ("LiteSpeed", re.compile(r"LiteSpeed", re.I)),
    ("Caddy", re.compile(r"Caddy", re.I)),
]

# (label, pattern) — applied to X-Powered-By header value
_POWERED_BY_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("PHP", re.compile(r"PHP", re.I)),
    ("Express", re.compile(r"Express", re.I)),
    ("ASP.NET", re.compile(r"ASP\.NET", re.I)),
    ("Next.js", re.compile(r"Next\.js", re.I)),
]

# (label, cookie_name_pattern) — applied to Set-Cookie header(s)
_COOKIE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("Java/Servlet", re.compile(r"JSESSIONID", re.I)),
    ("PHP", re.compile(r"PHPSESSID", re.I)),
    ("Node.js/Express", re.compile(r"connect\.sid", re.I)),
    ("Laravel", re.compile(r"laravel_session", re.I)),
    ("Django", re.compile(r"csrftoken|sessionid", re.I)),
]

# (label, body pattern) — applied to response HTML body
_BODY_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("WordPress", re.compile(r"wp-content|wp-includes|wordpress", re.I)),
    ("Drupal", re.compile(r"drupal", re.I)),
    ("Joomla", re.compile(r"joomla", re.I)),
    ("Laravel", re.compile(r"laravel", re.I)),
    ("Django", re.compile(r"csrfmiddlewaretoken", re.I)),
    ("React", re.compile(r"__NEXT_DATA__|react(?:dom)?\.min\.js", re.I)),
    ("Angular", re.compile(r"ng-version|angular\.min\.js", re.I)),
]

# (label, meta content pattern) — for <meta name="generator"> etc.
_META_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("WordPress", re.compile(r'<meta[^>]+content="WordPress', re.I)),
    ("Joomla", re.compile(r'<meta[^>]+content="Joomla', re.I)),
    ("Drupal", re.compile(r'<meta[^>]+content="Drupal', re.I)),
]


def _detect_from_response(resp: httpx.Response) -> list[str]:
    """Return a list of detected technology labels from the response."""
    found: list[str] = []
    seen: set[str] = set()

    def add(label: str) -> None:
        if label not in seen:
            seen.add(label)
            found.append(label)

    # Server header
    server = resp.headers.get("server", "")
    for label, pat in _SERVER_PATTERNS:
        if pat.search(server):
            add(label)
            # Include version info if present
            version_match = re.search(r"[\d.]+", server)
            if version_match:
                add(f"{label}/{version_match.group()}")

    # X-Powered-By
    powered_by = resp.headers.get("x-powered-by", "")
    for label, pat in _POWERED_BY_PATTERNS:
        if pat.search(powered_by):
            add(label)
            version_match = re.search(r"[\d.]+", powered_by)
            if version_match:
                add(f"{label}/{version_match.group()}")

    # Set-Cookie
    set_cookie = resp.headers.get("set-cookie", "")
    for label, pat in _COOKIE_PATTERNS:
        if pat.search(set_cookie):
            add(label)

    # Body patterns (limit body size to avoid huge responses)
    body = resp.text[:500_000] if resp.text else ""
    for label, pat in _BODY_PATTERNS:
        if pat.search(body):
            add(label)

    # Meta generator tags
    for label, pat in _META_PATTERNS:
        if pat.search(body):
            add(label)

    return found


class TechFingerprintPlugin(PluginBase):
    name = "tech_fingerprint"
    description = "Technology fingerprinting from HTTP response headers and body"
    category = "blackbox"
    phase = 1
    base_severity = Severity.INFO
    provides = ["tech_stack"]
    detection_criteria = "Known technology signature in response headers or body"
    expected_evidence = "Header value or body pattern matching known tech signature"

    def is_applicable(self, target: Target) -> bool:
        return bool(target.url)

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        try:
            async with httpx.AsyncClient(
                verify=target.verify_ssl,
                timeout=10,
                follow_redirects=True,
            ) as client:
                resp = await client.get(target.url)
        except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError,
                httpx.TimeoutException):
            return []

        detected = _detect_from_response(resp)
        if not detected:
            return []

        # Populate context.tech_stack (deduplicated)
        if context is not None:
            for tech in detected:
                if tech not in context.tech_stack:
                    context.tech_stack.append(tech)

        results: list[Result] = []
        for tech in detected:
            results.append(Result(
                plugin_name=self.name,
                base_severity=self.base_severity,
                title=f"Technology detected: {tech}",
                description=f"Identified '{tech}' from HTTP response analysis.",
                evidence=f"Detected technologies: {', '.join(detected)}",
                endpoint=target.url,
                recommendation=(
                    "Ensure the identified technology is up-to-date and properly hardened. "
                    "Consider hiding version information from response headers."
                ),
                rule_id="tech_detected",
            ))

        return results
