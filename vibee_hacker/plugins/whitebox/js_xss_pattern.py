"""Plugin: JavaScript XSS Pattern Detector (Phase 2, HIGH)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

SKIP_DIRS = ["node_modules", "venv", ".git", "dist", "build", "__pycache__", ".tox", "vendor"]
JS_EXTENSIONS = {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".vue"}

XSS_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("dangerouslySetInnerHTML", re.compile(r'\bdangerouslySetInnerHTML\b')),
    ("v-html directive", re.compile(r'\bv-html\b')),
    ("[innerHTML] binding", re.compile(r'\[innerHTML\]')),
    ("bypassSecurityTrust*", re.compile(r'\bbypassSecurityTrust\w*\s*\(')),
    ("outerHTML assignment", re.compile(r'\bouterHTML\s*=')),
]


def _should_skip(path: Path) -> bool:
    return any(skip in path.parts for skip in SKIP_DIRS)


class JsXssPatternPlugin(PluginBase):
    name = "js_xss_pattern"
    description = "Detect XSS-prone patterns in JavaScript/TypeScript (dangerouslySetInnerHTML, v-html, etc.)"
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
                for label, pat in XSS_PATTERNS:
                    if pat.search(line):
                        results.append(
                            Result(
                                plugin_name=self.name,
                                base_severity=Severity.HIGH,
                                title=f"XSS Pattern: {label}",
                                description=(
                                    f"Potential XSS via '{label}' in "
                                    f"'{src_file.relative_to(root)}' at line {lineno}."
                                ),
                                evidence=f"{src_file.relative_to(root)}:{lineno}: {line.strip()[:120]}",
                                recommendation=(
                                    "Avoid injecting raw HTML into the DOM. "
                                    "Use text-based rendering and DOMPurify for sanitization if HTML is required."
                                ),
                                cwe_id="CWE-79",
                                rule_id="js_xss_pattern",
                                endpoint=str(src_file),
                            )
                        )
                        break

        return results
