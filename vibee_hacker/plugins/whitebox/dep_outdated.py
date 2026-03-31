"""Plugin: Dependency Outdated Package Checker (Phase 4, LOW~MEDIUM)."""
from __future__ import annotations

import json
import re
from pathlib import Path

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

# Packages where 0.x or 1.x is considered very outdated because current is 3.x+
# Format: package_name_lower -> minimum acceptable major version
OUTDATED_THRESHOLDS: dict[str, int] = {
    # Python
    "django": 3,
    "flask": 2,
    "sqlalchemy": 2,
    "celery": 5,
    "pytest": 7,
    "requests": 2,
    "numpy": 1,
    "pandas": 2,
    "pillow": 9,
    "werkzeug": 2,
    "jinja2": 3,
    # JS
    "react": 16,
    "vue": 3,
    "angular": 12,
    "webpack": 5,
    "babel-core": 7,
    "eslint": 8,
    "jest": 27,
    "express": 4,
    "lodash": 4,
    "axios": 1,
}

_REQ_LINE_RE = re.compile(r"^([A-Za-z0-9_.\-]+)[=><!\s]+([0-9][0-9a-zA-Z.\-]*)")


def _major_version(version_str: str) -> int | None:
    """Extract major version number from a version string."""
    m = re.match(r"(\d+)", version_str.lstrip("^~>=<"))
    if m:
        return int(m.group(1))
    return None


def _parse_requirements(content: str) -> list[tuple[str, str]]:
    packages: list[tuple[str, str]] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = _REQ_LINE_RE.match(line)
        if m:
            packages.append((m.group(1).lower(), m.group(2)))
    return packages


def _parse_package_json(content: str) -> list[tuple[str, str]]:
    packages: list[tuple[str, str]] = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return packages
    for section in ("dependencies", "devDependencies"):
        for pkg, ver in data.get(section, {}).items():
            packages.append((pkg.lower(), str(ver)))
    return packages


class DepOutdatedPlugin(PluginBase):
    name = "dep_outdated"
    description = "Detect packages pinned to very old major versions (heuristic check)"
    category = "whitebox"
    phase = 4
    base_severity = Severity.LOW

    def is_applicable(self, target: Target) -> bool:
        return bool(target.path)

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.path:
            return []
        root = Path(target.path)
        if not root.exists():
            return []

        results: list[Result] = []

        def _check_packages(packages: list[tuple[str, str]], source_file: str) -> None:
            for pkg_name, version in packages:
                threshold = OUTDATED_THRESHOLDS.get(pkg_name)
                if threshold is None:
                    continue
                major = _major_version(version)
                if major is None:
                    continue
                if major < threshold:
                    results.append(Result(
                        plugin_name=self.name,
                        base_severity=Severity.LOW,
                        title=f"Outdated Dependency: {pkg_name}=={version}",
                        description=(
                            f"Package '{pkg_name}' is pinned to a very old version ({version}). "
                            f"The current major version line is {threshold}.x+. "
                            f"Old packages may lack security patches and active maintenance."
                        ),
                        evidence=f"{source_file}: {pkg_name}=={version}",
                        recommendation=(
                            f"Upgrade {pkg_name} to the latest stable release "
                            f"(major version >= {threshold})."
                        ),
                        cwe_id="CWE-1104",
                        rule_id="dep_outdated_package",
                        endpoint=str(root / source_file),
                    ))

        req_file = root / "requirements.txt"
        if req_file.is_file():
            try:
                content = req_file.read_text(errors="ignore")
            except OSError:
                content = ""
            _check_packages(_parse_requirements(content), "requirements.txt")

        pkg_json_file = root / "package.json"
        if pkg_json_file.is_file():
            try:
                content = pkg_json_file.read_text(errors="ignore")
            except OSError:
                content = ""
            _check_packages(_parse_package_json(content), "package.json")

        return results
