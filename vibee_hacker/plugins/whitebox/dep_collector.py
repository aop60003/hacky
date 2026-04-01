"""Plugin 3: Dependency Collector (Phase 1, INFO)."""
from __future__ import annotations

import json
import re
from pathlib import Path

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

DEP_FILES = [
    "requirements.txt",
    "package.json",
    "pom.xml",
    "go.mod",
    "Gemfile",
    "composer.json",
]


class DepCollectorPlugin(PluginBase):
    name = "dep_collector"
    description = "Collect project dependencies from manifest files"
    category = "whitebox"
    phase = 1
    base_severity = Severity.INFO

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.path:
            return []

        root = Path(target.path)
        if not root.exists():
            return []

        found_files: list[str] = []
        deps: list[str] = []

        for dep_file in DEP_FILES:
            candidate = root / dep_file
            if not candidate.exists():
                continue
            found_files.append(dep_file)
            try:
                content = candidate.read_text(errors="ignore")
            except OSError:
                continue

            if dep_file == "requirements.txt":
                for line in content.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        deps.append(line)

            elif dep_file == "package.json":
                try:
                    pkg = json.loads(content)
                    for section in ("dependencies", "devDependencies"):
                        for name, version in pkg.get(section, {}).items():
                            deps.append(f"{name}@{version}")
                except (json.JSONDecodeError, AttributeError):
                    pass

        if not found_files:
            return []

        deps_summary = ", ".join(deps[:20])
        if len(deps) > 20:
            deps_summary += f" ... (+{len(deps) - 20} more)"

        return [
            Result(
                plugin_name=self.name,
                base_severity=Severity.INFO,
                title="Dependencies Collected",
                description=(
                    f"Found {len(found_files)} dependency file(s): {', '.join(found_files)}. "
                    f"Total packages: {len(deps)}."
                ),
                evidence=f"Files: {', '.join(found_files)}; Packages: {deps_summary}",
                recommendation="Audit dependencies for known CVEs using tools like pip-audit or npm audit.",
                rule_id="dependencies_collected",
                endpoint=str(root),
            )
        ]
