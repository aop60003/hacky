"""Plugin: Dependency License Checker (Phase 4, INFO)."""
from __future__ import annotations

import json
import re
from pathlib import Path

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

# Copyleft licenses to flag
COPYLEFT_LICENSES = re.compile(
    r"\b(A?GPL|GNU\s+(?:Affero\s+)?(?:Lesser\s+)?General\s+Public\s+License|LGPL|EUPL|OSL|CDDL)\b",
    re.IGNORECASE,
)


def _is_copyleft(license_str: str) -> bool:
    return bool(COPYLEFT_LICENSES.search(license_str))


class DepLicenseCheckPlugin(PluginBase):
    name = "dep_license_check"
    description = "Flag GPL/AGPL licenses in package.json (potential copyleft contamination)"
    category = "whitebox"
    phase = 4
    base_severity = Severity.INFO

    def is_applicable(self, target: Target) -> bool:
        return bool(target.path)

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.path:
            return []
        root = Path(target.path)
        if not root.exists():
            return []

        results: list[Result] = []

        # Search all package.json files (but skip node_modules)
        for pkg_json_file in root.rglob("package.json"):
            # Skip node_modules and common build dirs
            if any(p in pkg_json_file.parts for p in ("node_modules", "vendor", "dist", "build")):
                continue
            try:
                content = pkg_json_file.read_text(errors="ignore")
            except OSError:
                continue

            try:
                data = json.loads(content)
            except json.JSONDecodeError:
                # Fallback: raw text scan for license field
                m = re.search(r'"license"\s*:\s*"([^"]+)"', content)
                if m and _is_copyleft(m.group(1)):
                    license_val = m.group(1)
                    results.append(_make_result(self.name, pkg_json_file, root, license_val))
                continue

            # Check top-level license
            license_val = data.get("license", "")
            if isinstance(license_val, str) and _is_copyleft(license_val):
                results.append(_make_result(self.name, pkg_json_file, root, license_val))
            elif isinstance(license_val, list):
                for lic in license_val:
                    ltype = lic.get("type", "") if isinstance(lic, dict) else str(lic)
                    if _is_copyleft(ltype):
                        results.append(_make_result(self.name, pkg_json_file, root, ltype))
                        break

        return results


def _make_result(plugin_name: str, pkg_file: Path, root: Path, license_val: str) -> Result:
    rel = str(pkg_file.relative_to(root))
    return Result(
        plugin_name=plugin_name,
        base_severity=Severity.INFO,
        title=f"Copyleft License Detected: {license_val}",
        description=(
            f"Package file '{rel}' declares a copyleft license ({license_val}). "
            "GPL/AGPL-licensed dependencies may impose copyleft obligations on proprietary projects."
        ),
        evidence=f"{rel}: license = {license_val!r}",
        recommendation=(
            "Review legal implications of using this copyleft-licensed package. "
            "Consider replacing with a permissively-licensed alternative (MIT, Apache-2.0) "
            "if copyleft obligations are unacceptable."
        ),
        cwe_id=None,
        rule_id="dep_license_concern",
        endpoint=str(pkg_file),
    )
