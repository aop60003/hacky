# vibee_hacker/plugins/blackbox/dir_enum.py
"""Directory/file brute-force enumeration plugin (P2-1)."""

from __future__ import annotations

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/.svn/entries",
    "/backup.sql",
    "/database.sql",
    "/dump.sql",
    "/wp-config.php",
    "/config.php",
    "/configuration.php",
    "/.htaccess",
    "/.htpasswd",
    "/web.config",
    "/phpinfo.php",
    "/info.php",
    "/admin/",
    "/administrator/",
    "/wp-admin/",
    "/.DS_Store",
    "/Thumbs.db",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/package.json",
    "/composer.json",
]

# Generic error indicators that suggest a catch-all page, not real content
_GENERIC_ERROR_MARKERS = (
    "404 not found",
    "page not found",
    "not found",
    "error 404",
    "the page you requested",
    "no such file",
    "object not found",
)

_CRITICAL_PATHS = {
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/.svn/entries",
    "/backup.sql",
    "/database.sql",
    "/dump.sql",
}

_HIGH_PATHS = {
    "/wp-config.php",
    "/config.php",
    "/configuration.php",
    "/.htaccess",
    "/.htpasswd",
    "/web.config",
}

_MEDIUM_PATHS = {
    "/phpinfo.php",
    "/info.php",
    "/admin/",
    "/administrator/",
    "/wp-admin/",
    "/.DS_Store",
    "/Thumbs.db",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/package.json",
    "/composer.json",
}


def _severity_for_path(path: str) -> Severity:
    if path in _CRITICAL_PATHS:
        return Severity.CRITICAL
    if path in _HIGH_PATHS:
        return Severity.HIGH
    return Severity.MEDIUM


def _is_generic_error(body: str) -> bool:
    lower = body.lower()
    return any(marker in lower for marker in _GENERIC_ERROR_MARKERS)


class DirEnumPlugin(PluginBase):
    name = "dir_enum"
    description = "Brute-force common sensitive paths to discover exposed files"
    category = "blackbox"
    phase = 3
    base_severity = Severity.HIGH
    detection_criteria = "HTTP 200 with > 50 bytes of non-error content at a sensitive path"
    cwe_id = "CWE-538"
    destructive_level = 0

    def is_applicable(self, target: Target) -> bool:
        return bool(target.url)

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        base = target.url.rstrip("/")
        results: list[Result] = []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            for path in SENSITIVE_PATHS:
                url = base + path
                try:
                    resp = await client.get(url)
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    # Treat all transport errors as not found
                    continue

                if resp.status_code != 200:
                    continue

                body = resp.text
                if len(body) <= 50:
                    continue

                if _is_generic_error(body):
                    continue

                severity = _severity_for_path(path)
                results.append(Result(
                    plugin_name=self.name,
                    base_severity=severity,
                    title=f"Sensitive file exposed: {path}",
                    description=(
                        f"The path {path} is publicly accessible and returned "
                        f"a {resp.status_code} response with {len(body)} bytes of content. "
                        "This may expose sensitive configuration data, credentials, or source history."
                    ),
                    recommendation=(
                        f"Restrict access to {path} via web server configuration or remove the file."
                    ),
                    cwe_id="CWE-538",
                    evidence=body[:500],
                    endpoint=url,
                    rule_id="dir_enum_sensitive_file",
                ))

        return results
