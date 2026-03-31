"""Plugin: Python Django Security Checker (Phase 2, HIGH)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

SKIP_DIRS = ["node_modules", "venv", ".git", "dist", "build", "__pycache__", ".tox", "vendor"]

# (label, pattern, rule_id suffix, severity)
DJANGO_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("DEBUG = True", re.compile(r'^\s*DEBUG\s*=\s*True\s*$'), "py_django_debug"),
    ("@csrf_exempt decorator", re.compile(r'@csrf_exempt\b'), "py_django_csrf_exempt"),
    ("Hardcoded SECRET_KEY", re.compile(r"^\s*SECRET_KEY\s*=\s*['\"][^'\"]{8,}['\"]"), "py_django_secret_key"),
    ("ALLOWED_HOSTS = ['*']", re.compile(r"ALLOWED_HOSTS\s*=\s*\[\s*['\"]?\*['\"]?\s*\]"), "py_django_allowed_hosts"),
]

# Skip if SECRET_KEY comes from environment
SECRET_KEY_ENV_PATTERN = re.compile(r'os\.(environ|getenv)')


def _should_skip(path: Path) -> bool:
    return any(skip in path.parts for skip in SKIP_DIRS)


class PyDjangoCheckPlugin(PluginBase):
    name = "py_django_check"
    description = "Detect Django-specific security misconfigurations (DEBUG=True, csrf_exempt, etc.)"
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
                for label, pat, rule_id in DJANGO_PATTERNS:
                    if pat.search(line):
                        # Skip SECRET_KEY if it references env vars
                        if rule_id == "py_django_secret_key" and SECRET_KEY_ENV_PATTERN.search(line):
                            continue
                        results.append(
                            Result(
                                plugin_name=self.name,
                                base_severity=Severity.HIGH,
                                title=f"Django Security Issue: {label}",
                                description=(
                                    f"Django security misconfiguration '{label}' detected in "
                                    f"'{src_file.relative_to(root)}' at line {lineno}."
                                ),
                                evidence=f"{src_file.relative_to(root)}:{lineno}: {line.strip()[:120]}",
                                recommendation=(
                                    f"Fix the Django configuration issue: {label}. "
                                    "Refer to Django security checklist for production settings."
                                ),
                                cwe_id="CWE-16",
                                rule_id=rule_id,
                                endpoint=str(src_file),
                            )
                        )
                        break

        return results
