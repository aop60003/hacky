"""Plugin: Dependency Known Vulnerability Checker (Phase 4, varies)."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import NamedTuple

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase


class VulnEntry(NamedTuple):
    pkg: str
    max_safe_version: tuple[int, ...]  # minimum version that is safe (exclusive lower bound)
    cve: str
    severity: Severity


# Known vulnerable packages — versions strictly less than max_safe_version are flagged.
PYTHON_VULNS: list[VulnEntry] = [
    VulnEntry("django", (3, 2, 25), "CVE-2024-27351", Severity.HIGH),
    VulnEntry("requests", (2, 31, 0), "CVE-2023-32681", Severity.MEDIUM),
    VulnEntry("flask", (2, 3, 3), "CVE-2023-30861", Severity.HIGH),
    VulnEntry("jinja2", (3, 1, 3), "CVE-2024-22195", Severity.MEDIUM),
]

JS_VULNS: list[VulnEntry] = [
    VulnEntry("lodash", (4, 17, 21), "CVE-2021-23337", Severity.HIGH),
    VulnEntry("axios", (1, 6, 0), "CVE-2023-45857", Severity.HIGH),
    VulnEntry("express", (4, 18, 2), "CVE-2022-24999", Severity.MEDIUM),
    VulnEntry("jsonwebtoken", (9, 0, 0), "CVE-2022-23529", Severity.CRITICAL),
]

_REQ_LINE_RE = re.compile(r"^([A-Za-z0-9_.\-]+)[=><!\s]+([0-9][0-9a-zA-Z.\-]*)")


def _parse_version(version_str: str) -> tuple[int, ...] | None:
    """Parse a semver-like string into a tuple of ints for comparison."""
    parts = re.split(r"[.\-]", version_str)
    try:
        return tuple(int(p) for p in parts if p.isdigit())
    except ValueError:
        return None


def _is_vulnerable(version_str: str, min_safe: tuple[int, ...]) -> bool:
    """Return True if version < min_safe."""
    ver = _parse_version(version_str)
    if ver is None:
        return False
    # Pad shorter tuple with zeros for comparison
    length = max(len(ver), len(min_safe))
    v1 = ver + (0,) * (length - len(ver))
    v2 = min_safe + (0,) * (length - len(min_safe))
    return v1 < v2


def _parse_requirements(content: str) -> list[tuple[str, str]]:
    """Return list of (package_name_lower, version) from requirements.txt content."""
    results: list[tuple[str, str]] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = _REQ_LINE_RE.match(line)
        if m:
            results.append((m.group(1).lower(), m.group(2)))
    return results


def _parse_package_json(content: str) -> list[tuple[str, str]]:
    """Return list of (package_name_lower, version) from package.json content."""
    results: list[tuple[str, str]] = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return results
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for pkg, ver in data.get(section, {}).items():
            # Strip leading ^, ~, >=, etc.
            ver_clean = re.sub(r"^[^0-9]*", "", str(ver))
            results.append((pkg.lower(), ver_clean))
    return results


class DepVulnCheckPlugin(PluginBase):
    name = "dep_vuln_check"
    description = "Check dependencies against known vulnerable versions (requirements.txt, package.json)"
    category = "whitebox"
    phase = 4
    base_severity = Severity.HIGH

    def is_applicable(self, target: Target) -> bool:
        return bool(target.path)

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.path:
            return []
        root = Path(target.path)
        if not root.exists():
            return []

        results: list[Result] = []

        # --- requirements.txt ---
        req_file = root / "requirements.txt"
        if req_file.is_file():
            try:
                content = req_file.read_text(errors="ignore")
            except OSError:
                content = ""
            packages = _parse_requirements(content)
            for pkg_name, version in packages:
                for entry in PYTHON_VULNS:
                    if pkg_name == entry.pkg and _is_vulnerable(version, entry.max_safe_version):
                        safe_ver = ".".join(str(x) for x in entry.max_safe_version)
                        results.append(Result(
                            plugin_name=self.name,
                            base_severity=entry.severity,
                            title=f"Vulnerable Dependency: {pkg_name}=={version}",
                            description=(
                                f"Package '{pkg_name}' version {version} is affected by {entry.cve}. "
                                f"Upgrade to >= {safe_ver}."
                            ),
                            evidence=f"requirements.txt: {pkg_name}=={version}",
                            recommendation=f"Upgrade {pkg_name} to >= {safe_ver}.",
                            cwe_id="CWE-1104",
                            rule_id="dep_known_vulnerability",
                            endpoint=str(req_file),
                        ))
                        break

        # --- package.json ---
        pkg_json_file = root / "package.json"
        if pkg_json_file.is_file():
            try:
                content = pkg_json_file.read_text(errors="ignore")
            except OSError:
                content = ""
            packages = _parse_package_json(content)
            for pkg_name, version in packages:
                for entry in JS_VULNS:
                    if pkg_name == entry.pkg and _is_vulnerable(version, entry.max_safe_version):
                        safe_ver = ".".join(str(x) for x in entry.max_safe_version)
                        results.append(Result(
                            plugin_name=self.name,
                            base_severity=entry.severity,
                            title=f"Vulnerable JS Dependency: {pkg_name}@{version}",
                            description=(
                                f"Package '{pkg_name}' version {version} is affected by {entry.cve}. "
                                f"Upgrade to >= {safe_ver}."
                            ),
                            evidence=f"package.json: {pkg_name}@{version}",
                            recommendation=f"Upgrade {pkg_name} to >= {safe_ver}.",
                            cwe_id="CWE-1104",
                            rule_id="dep_known_vulnerability",
                            endpoint=str(pkg_json_file),
                        ))
                        break

        return results
