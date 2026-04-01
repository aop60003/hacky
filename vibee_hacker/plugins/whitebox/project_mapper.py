"""Plugin 2: Project Mapper (Phase 1, INFO)."""
from __future__ import annotations

from pathlib import Path

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

SKIP_DIRS = ["node_modules", "venv", ".git", "dist", "build", "__pycache__", ".tox", "vendor"]

ENTRY_POINTS = ["main.py", "app.py", "index.js", "server.js", "manage.py"]
CONFIG_FILES = ["settings.py", ".env", "config.js", "application.yml", "application.yaml"]


def _should_skip(path: Path) -> bool:
    return any(skip in path.parts for skip in SKIP_DIRS)


class ProjectMapperPlugin(PluginBase):
    name = "project_mapper"
    description = "Map project structure: entry points, config files, total file/line counts"
    category = "whitebox"
    phase = 1
    base_severity = Severity.INFO

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.path:
            return []

        root = Path(target.path)
        if not root.exists():
            return []

        found_entries: list[str] = []
        found_configs: list[str] = []
        total_files = 0
        total_lines = 0

        for f in root.rglob("*"):
            if not f.is_file() or _should_skip(f):
                continue
            total_files += 1
            try:
                content = f.read_text(errors="ignore")
                total_lines += content.count("\n") + 1
            except OSError:
                pass
            if f.name in ENTRY_POINTS:
                found_entries.append(str(f.relative_to(root)))
            if f.name in CONFIG_FILES:
                found_configs.append(str(f.relative_to(root)))

        evidence_parts = [
            f"Total files: {total_files}",
            f"Total lines: {total_lines}",
            f"Entry points: {', '.join(found_entries) or 'none'}",
            f"Config files: {', '.join(found_configs) or 'none'}",
        ]
        evidence = "; ".join(evidence_parts)

        return [
            Result(
                plugin_name=self.name,
                base_severity=Severity.INFO,
                title="Project Structure Mapped",
                description=(
                    f"Found {total_files} files ({total_lines} lines). "
                    f"Entry points: {', '.join(found_entries) or 'none'}. "
                    f"Config files: {', '.join(found_configs) or 'none'}."
                ),
                evidence=evidence,
                recommendation="Review entry points and config files for security issues.",
                rule_id="project_map",
                endpoint=str(root),
            )
        ]
