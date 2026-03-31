"""Plugin: Python Flask Security Checker (Phase 2, HIGH)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

SKIP_DIRS = ["node_modules", "venv", ".git", "dist", "build", "__pycache__", ".tox", "vendor"]

FLASK_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    (
        "app.run(debug=True)",
        re.compile(r'\bapp\.run\s*\([^)]*debug\s*=\s*True'),
        "py_flask_debug",
    ),
    (
        "Hardcoded secret_key",
        re.compile(r'\bapp\.secret_key\s*=\s*["\'][^"\']{1,}["\']'),
        "py_flask_secret_key",
    ),
    (
        "render_template_string with user input",
        re.compile(r'\brender_template_string\s*\('),
        "py_flask_template_string",
    ),
]

ENV_PATTERN = re.compile(r'os\.(environ|getenv)|environ\.get')


def _should_skip(path: Path) -> bool:
    return any(skip in path.parts for skip in SKIP_DIRS)


class PyFlaskCheckPlugin(PluginBase):
    name = "py_flask_check"
    description = "Detect Flask-specific security misconfigurations (debug=True, hardcoded secret_key, etc.)"
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
                for label, pat, rule_id in FLASK_PATTERNS:
                    if pat.search(line):
                        # Skip if secret_key is from environment variable
                        if rule_id == "py_flask_secret_key" and ENV_PATTERN.search(line):
                            continue
                        results.append(
                            Result(
                                plugin_name=self.name,
                                base_severity=Severity.HIGH,
                                title=f"Flask Security Issue: {label}",
                                description=(
                                    f"Flask security misconfiguration '{label}' detected in "
                                    f"'{src_file.relative_to(root)}' at line {lineno}."
                                ),
                                evidence=f"{src_file.relative_to(root)}:{lineno}: {line.strip()[:120]}",
                                recommendation=(
                                    f"Fix the Flask configuration issue: {label}. "
                                    "Never run debug=True in production; store secrets in env vars."
                                ),
                                cwe_id="CWE-16",
                                rule_id=rule_id,
                                endpoint=str(src_file),
                            )
                        )
                        break

        return results
