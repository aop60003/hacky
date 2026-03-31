"""Plugin: Python FastAPI Security Checker (Phase 2, HIGH)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

SKIP_DIRS = ["node_modules", "venv", ".git", "dist", "build", "__pycache__", ".tox", "vendor"]

FASTAPI_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    (
        "CORSMiddleware with allow_origins=['*']",
        re.compile(r'allow_origins\s*=\s*\[\s*["\'][*]["\']'),
        "py_fastapi_cors_wildcard",
    ),
]


def _should_skip(path: Path) -> bool:
    return any(skip in path.parts for skip in SKIP_DIRS)


class PyFastapiCheckPlugin(PluginBase):
    name = "py_fastapi_check"
    description = "Detect FastAPI-specific security misconfigurations (CORS wildcard, etc.)"
    category = "whitebox"
    phase = 2
    base_severity = Severity.HIGH

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.path:
            return []

        root = Path(target.path)
        if not root.exists():
            return []

        results: list[Result] = []

        for src_file in root.rglob("*.py"):
            if not src_file.is_file() or _should_skip(src_file):
                continue
            try:
                content = src_file.read_text(errors="ignore")
            except OSError:
                continue

            for lineno, line in enumerate(content.splitlines(), start=1):
                for label, pat, rule_id in FASTAPI_PATTERNS:
                    if pat.search(line):
                        results.append(
                            Result(
                                plugin_name=self.name,
                                base_severity=Severity.HIGH,
                                title=f"FastAPI Security Issue: {label}",
                                description=(
                                    f"FastAPI security misconfiguration '{label}' detected in "
                                    f"'{src_file.relative_to(root)}' at line {lineno}."
                                ),
                                evidence=f"{src_file.relative_to(root)}:{lineno}: {line.strip()[:120]}",
                                recommendation=(
                                    "Restrict CORS origins to specific trusted domains. "
                                    "Using allow_origins=['*'] exposes your API to cross-origin attacks."
                                ),
                                cwe_id="CWE-16",
                                rule_id=rule_id,
                                endpoint=str(src_file),
                            )
                        )
                        break

        return results
