"""Plugin: Python Template Injection Pattern Detector (Phase 2, HIGH)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

SKIP_DIRS = ["node_modules", "venv", ".git", "dist", "build", "__pycache__", ".tox", "vendor"]

TEMPLATE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("Jinja2 |safe filter", re.compile(r'\|\s*safe\b')),
    ("autoescape=False", re.compile(r'\bautoescape\s*=\s*False')),
    ("Markup()", re.compile(r'\bMarkup\s*\(')),
    ("render_template_string()", re.compile(r'\brender_template_string\s*\(')),
    ("Environment.from_string()", re.compile(r'\b(env|environment|Environment)\b.*\.from_string\s*\(')),
    ("Jinja2 Environment without autoescape", re.compile(r'\bEnvironment\s*\(')),
]


def _should_skip(path: Path) -> bool:
    return any(skip in path.parts for skip in SKIP_DIRS)


class PyTemplatePatternPlugin(PluginBase):
    name = "py_template_pattern"
    description = "Detect template injection patterns in Python (Jinja2 |safe, autoescape=False, etc.)"
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
                for label, pat in TEMPLATE_PATTERNS:
                    if pat.search(line):
                        results.append(
                            Result(
                                plugin_name=self.name,
                                base_severity=Severity.HIGH,
                                title=f"Template Injection Pattern: {label}",
                                description=(
                                    f"Potential XSS/template injection via '{label}' in "
                                    f"'{src_file.relative_to(root)}' at line {lineno}."
                                ),
                                evidence=f"{src_file.relative_to(root)}:{lineno}: {line.strip()[:120]}",
                                recommendation=(
                                    "Enable autoescaping, avoid the |safe filter with user input, "
                                    "and do not pass raw user data to render_template_string()."
                                ),
                                cwe_id="CWE-79",
                                rule_id="py_template_injection",
                                endpoint=str(src_file),
                            )
                        )
                        break

        return results
