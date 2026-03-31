"""Plugin: JavaScript Dangerous Functions Detector (Phase 2, CRITICAL)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

SKIP_DIRS = ["node_modules", "venv", ".git", "dist", "build", "__pycache__", ".tox", "vendor"]
JS_EXTENSIONS = {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}

DANGEROUS_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("eval()", re.compile(r'\beval\s*\(')),
    ("new Function()", re.compile(r'\bnew\s+Function\s*\(')),
    ("Function() constructor", re.compile(r'(?<!\w)Function\s*\(')),
    ("innerHTML =", re.compile(r'\binnerHTML\s*=')),
    ("document.write()", re.compile(r'\bdocument\.write\s*\(')),
    ("setTimeout with string", re.compile(r'\bsetTimeout\s*\(\s*["\']')),
    ("setInterval with string", re.compile(r'\bsetInterval\s*\(\s*["\']')),
]


def _should_skip(path: Path) -> bool:
    return any(skip in path.parts for skip in SKIP_DIRS)


class JsDangerousFuncsPlugin(PluginBase):
    name = "js_dangerous_funcs"
    description = "Detect dangerous JavaScript functions (eval, innerHTML, document.write, etc.)"
    category = "whitebox"
    phase = 2
    base_severity = Severity.CRITICAL

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.path:
            return []

        root = Path(target.path)
        if not root.exists():
            return []

        results: list[Result] = []

        for src_file in root.rglob("*"):
            if not src_file.is_file() or src_file.suffix.lower() not in JS_EXTENSIONS:
                continue
            if _should_skip(src_file):
                continue
            try:
                content = src_file.read_text(errors="ignore")
            except OSError:
                continue

            for lineno, line in enumerate(content.splitlines(), start=1):
                for label, pat in DANGEROUS_PATTERNS:
                    if pat.search(line):
                        results.append(
                            Result(
                                plugin_name=self.name,
                                base_severity=Severity.CRITICAL,
                                title=f"Dangerous JS Function: {label}",
                                description=(
                                    f"Use of '{label}' detected in "
                                    f"'{src_file.relative_to(root)}' at line {lineno}. "
                                    "This can lead to XSS or remote code execution."
                                ),
                                evidence=f"{src_file.relative_to(root)}:{lineno}: {line.strip()[:120]}",
                                recommendation=(
                                    f"Avoid using {label}. Use safe DOM APIs like "
                                    "textContent instead of innerHTML."
                                ),
                                cwe_id="CWE-94",
                                rule_id="js_dangerous_func",
                                endpoint=str(src_file),
                            )
                        )
                        break

        return results
