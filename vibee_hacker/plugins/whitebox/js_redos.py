"""Plugin: JavaScript ReDoS Pattern Detector (Phase 2, HIGH)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

SKIP_DIRS = ["node_modules", "venv", ".git", "dist", "build", "__pycache__", ".tox", "vendor"]
JS_EXTENSIONS = {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}

# new RegExp(variable) — where arg is not a string literal
NEW_REGEXP_VAR_PATTERN = re.compile(r'\bnew\s+RegExp\s*\(\s*(?!["\'/])')

# ReDoS-vulnerable nested quantifier patterns in regex literals
NESTED_QUANTIFIER_PATTERN = re.compile(
    r'/(?:[^/\\]|\\.)*'           # start of regex literal
    r'(?:'
    r'\([^)]*[+*]\)[+*?]'         # (a+)+ or (a+)*
    r'|'
    r'\([^)]*\|[^)]*\)[+*?]'      # (a|b)*
    r'|'
    r'\[[^\]]+\][+*]\w*[+*]'      # [a-z]+x+
    r')'
    r'(?:[^/\\]|\\.)*/'
)

REDOS_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("new RegExp(variable)", NEW_REGEXP_VAR_PATTERN),
    ("nested quantifier regex", NESTED_QUANTIFIER_PATTERN),
]


def _should_skip(path: Path) -> bool:
    return any(skip in path.parts for skip in SKIP_DIRS)


class JsRedosPlugin(PluginBase):
    name = "js_redos"
    description = "Detect ReDoS-vulnerable patterns in JavaScript (new RegExp(userInput), nested quantifiers)"
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
                for label, pat in REDOS_PATTERNS:
                    if pat.search(line):
                        results.append(
                            Result(
                                plugin_name=self.name,
                                base_severity=Severity.HIGH,
                                title=f"ReDoS Vulnerability: {label}",
                                description=(
                                    f"Potential ReDoS vulnerability via '{label}' in "
                                    f"'{src_file.relative_to(root)}' at line {lineno}. "
                                    "User-controlled regex or nested quantifiers can cause catastrophic backtracking."
                                ),
                                evidence=f"{src_file.relative_to(root)}:{lineno}: {line.strip()[:120]}",
                                recommendation=(
                                    "Do not construct regex from user input. "
                                    "Audit regex patterns for nested quantifiers and use safe-regex or re2."
                                ),
                                cwe_id="CWE-1333",
                                rule_id="js_redos",
                                endpoint=str(src_file),
                            )
                        )
                        break

        return results
