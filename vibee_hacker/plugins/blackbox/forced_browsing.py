# vibee_hacker/plugins/blackbox/forced_browsing.py
"""Forced browsing / sensitive file exposure detection plugin."""

from __future__ import annotations

import re
import shlex
from urllib.parse import urlparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

# (path, list of signature patterns)
SENSITIVE_FILES: list[tuple[str, list[re.Pattern]]] = [
    ("/.env", [re.compile(r"DB_PASSWORD", re.I), re.compile(r"APP_SECRET", re.I), re.compile(r"API_KEY", re.I)]),
    ("/.git/config", [re.compile(r"\[core\]", re.I), re.compile(r"repositoryformatversion", re.I)]),
    ("/wp-config.php", [re.compile(r"DB_NAME", re.I), re.compile(r"DB_PASSWORD", re.I)]),
    ("/config.php", [re.compile(r"<\?php", re.I), re.compile(r"password", re.I)]),
    ("/web.config", [re.compile(r"<configuration>", re.I), re.compile(r"connectionStrings", re.I)]),
    ("/.htaccess", [re.compile(r"RewriteEngine", re.I), re.compile(r"AuthType", re.I)]),
    ("/backup.sql", [re.compile(r"CREATE TABLE", re.I), re.compile(r"INSERT INTO", re.I)]),
    ("/database.sql", [re.compile(r"CREATE TABLE", re.I), re.compile(r"INSERT INTO", re.I)]),
    ("/.svn/entries", [re.compile(r"svn", re.I), re.compile(r"dir", re.I)]),
]


def _base_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


class ForcedBrowsingPlugin(PluginBase):
    name = "forced_browsing"
    description = "Detect exposed sensitive files via forced browsing"
    category = "blackbox"
    phase = 3
    base_severity = Severity.HIGH
    detection_criteria = "Sensitive file path returns 200 with content matching known file signatures"
    expected_evidence = "Sensitive file content pattern matched in HTTP 200 response"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        base = _base_url(target.url)
        results: list[Result] = []

        async with httpx.AsyncClient(
            verify=target.verify_ssl,
            timeout=10,
            follow_redirects=False,
        ) as client:
            for path, signatures in SENSITIVE_FILES:
                endpoint = base + path
                try:
                    resp = await client.get(endpoint)
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                if resp.status_code != 200:
                    continue

                if len(resp.text) > 1_000_000:
                    continue

                matched_patterns: list[str] = []
                for sig in signatures:
                    if sig.search(resp.text):
                        matched_patterns.append(sig.pattern)

                # Require at least min(2, total_signatures) matches to reduce false positives
                required_matches = min(2, len(signatures))
                if len(matched_patterns) < required_matches:
                    continue

                if matched_patterns:
                    results.append(Result(
                        plugin_name=self.name,
                        base_severity=self.base_severity,
                        title=f"Sensitive file exposed: {path}",
                        description=(
                            f"The sensitive file {endpoint} is publicly accessible and its content "
                            f"matches known file signatures. This can expose credentials, configuration "
                            f"details, database dumps, or source control history to attackers."
                        ),
                        evidence=f"Path: {path} | Signatures matched: {matched_patterns} | Status: {resp.status_code}",
                        cwe_id="CWE-425",
                        endpoint=endpoint,
                        curl_command=f"curl {shlex.quote(endpoint)}",
                        rule_id="forced_browsing_sensitive_file",
                    ))
                    return results  # Stop on first finding

        return results
