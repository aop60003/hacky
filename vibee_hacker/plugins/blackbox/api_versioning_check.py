# vibee_hacker/plugins/blackbox/api_versioning_check.py
"""API versioning check plugin — detect active outdated API versions."""

from __future__ import annotations

import re
import shlex
from urllib.parse import urlparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

# Match /api/v2/, /v3/users, /api/v10/endpoint, etc.
VERSION_PATTERN = re.compile(r"(/(?:api/)?)(v)(\d+)(/)", re.I)


def _base_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _extract_version_info(url: str) -> tuple[int, str] | None:
    """Return (current_version_number, prefix_path) or None if no version found."""
    parsed = urlparse(url)
    path = parsed.path
    m = VERSION_PATTERN.search(path)
    if not m:
        return None
    version_num = int(m.group(3))
    # Build the base path prefix up to the version segment
    prefix = parsed.scheme + "://" + parsed.netloc + m.group(1)
    return version_num, prefix


class ApiVersioningCheckPlugin(PluginBase):
    name = "api_versioning_check"
    description = "Detect active outdated/deprecated API versions"
    category = "blackbox"
    phase = 2
    base_severity = Severity.MEDIUM
    detection_criteria = "Older API version endpoint returns HTTP 200"
    expected_evidence = "Older API version (/api/v1/) responds with 200 when current version is higher"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        version_info = _extract_version_info(target.url)
        if version_info is None:
            return []

        current_version, prefix = version_info
        if current_version <= 1:
            return []  # Already on v1 or v0 — nothing older to check

        results: list[Result] = []

        # Check versions from (current-1) down to v1
        versions_to_check = list(range(current_version - 1, 0, -1))

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            for old_ver in versions_to_check:
                old_url = f"{prefix}v{old_ver}/"
                try:
                    resp = await client.get(old_url)
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                if resp.status_code == 200:
                    results.append(Result(
                        plugin_name=self.name,
                        base_severity=self.base_severity,
                        title=f"Outdated API version v{old_ver} still active",
                        description=(
                            f"API version v{old_ver} is still active and returns HTTP 200 at {old_url}. "
                            f"Current version is v{current_version}. Outdated API versions may lack "
                            f"security patches and expose deprecated functionality."
                        ),
                        evidence=(
                            f"GET {old_url} returned HTTP {resp.status_code}; "
                            f"current version is v{current_version}"
                        ),
                        recommendation=(
                            "Decommission outdated API versions or require explicit opt-in. "
                            "Return 410 Gone for deprecated endpoints and notify API consumers."
                        ),
                        cwe_id="CWE-1104",
                        endpoint=old_url,
                        curl_command=f"curl -s {shlex.quote(old_url)}",
                        rule_id="api_old_version_active",
                    ))
                    return results  # Stop on first finding

        return results
