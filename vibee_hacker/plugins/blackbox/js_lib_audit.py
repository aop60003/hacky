# vibee_hacker/plugins/blackbox/js_lib_audit.py
"""JavaScript library vulnerability audit plugin."""

from __future__ import annotations

import re
import shlex
from typing import NamedTuple

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase


class VulnLib(NamedTuple):
    name: str
    url_pattern: re.Pattern[str]
    version_pattern: re.Pattern[str]
    max_safe_version: tuple[int, ...]
    cve_ref: str


# Known vulnerable library patterns
# url_pattern matches the script src URL
# version_pattern extracts the version string
VULNERABLE_LIBS: list[VulnLib] = [
    VulnLib(
        name="jQuery",
        url_pattern=re.compile(r"jquery[-.](\d+\.\d+(?:\.\d+)?)", re.I),
        version_pattern=re.compile(r"jquery[-.](\d+\.\d+(?:\.\d+)?)", re.I),
        max_safe_version=(3, 5, 0),
        cve_ref="CVE-2019-11358, CVE-2020-11022",
    ),
    VulnLib(
        name="AngularJS",
        url_pattern=re.compile(r"angular(?:\.min)?(?:\.js)?[-/](\d+\.\d+(?:\.\d+)?)", re.I),
        version_pattern=re.compile(r"angular(?:\.min)?(?:\.js)?[-/](\d+\.\d+(?:\.\d+)?)", re.I),
        max_safe_version=(1, 8, 0),
        cve_ref="CVE-2019-14863",
    ),
    VulnLib(
        name="Bootstrap",
        url_pattern=re.compile(r"bootstrap[-.](\d+\.\d+(?:\.\d+)?)", re.I),
        version_pattern=re.compile(r"bootstrap[-.](\d+\.\d+(?:\.\d+)?)", re.I),
        max_safe_version=(4, 3, 1),
        cve_ref="CVE-2019-8331",
    ),
]

SCRIPT_SRC_PATTERN = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)


def _parse_version(ver_str: str) -> tuple[int, ...]:
    parts = ver_str.split(".")
    result = []
    for p in parts:
        try:
            result.append(int(p))
        except ValueError:
            result.append(0)
    return tuple(result)


def _version_less_than(v: tuple[int, ...], threshold: tuple[int, ...]) -> bool:
    for a, b in zip(v, threshold):
        if a < b:
            return True
        if a > b:
            return False
    return len(v) < len(threshold)


class JsLibAuditPlugin(PluginBase):
    name = "js_lib_audit"
    description = "Audit JavaScript library versions for known vulnerabilities"
    category = "blackbox"
    phase = 2
    base_severity = Severity.MEDIUM
    detection_criteria = "Script tag references a known-vulnerable JavaScript library version"
    expected_evidence = "Script src URL contains a library name and version below the safe threshold"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        results: list[Result] = []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            try:
                resp = await client.get(target.url)
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

            if resp.status_code not in range(200, 300):
                return []

            if len(resp.text) > 2_000_000:
                return []

            script_srcs = SCRIPT_SRC_PATTERN.findall(resp.text)
            if not script_srcs:
                return []

            seen: set[str] = set()
            for src in script_srcs:
                for lib in VULNERABLE_LIBS:
                    m = lib.url_pattern.search(src)
                    if not m:
                        continue
                    ver_str = m.group(1)
                    version = _parse_version(ver_str)
                    dedup_key = f"{lib.name}-{ver_str}"
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    if _version_less_than(version, lib.max_safe_version):
                        results.append(Result(
                            plugin_name=self.name,
                            base_severity=self.base_severity,
                            title=f"Vulnerable {lib.name} version {ver_str} detected",
                            description=(
                                f"The page at {target.url} loads {lib.name} version {ver_str} "
                                f"which is below the minimum safe version "
                                f"{'.'.join(str(x) for x in lib.max_safe_version)}. "
                                f"This version has known security vulnerabilities ({lib.cve_ref})."
                            ),
                            evidence=f"Script src: {src} | Version: {ver_str} | Safe threshold: {'.'.join(str(x) for x in lib.max_safe_version)}",
                            recommendation=(
                                f"Upgrade {lib.name} to version {'.'.join(str(x) for x in lib.max_safe_version)} "
                                f"or later. Consider using a package manager for dependency management."
                            ),
                            cwe_id="CWE-1104",
                            endpoint=target.url,
                            curl_command=f"curl -s {shlex.quote(target.url)}",
                            rule_id="js_lib_vulnerable",
                        ))

        return results
