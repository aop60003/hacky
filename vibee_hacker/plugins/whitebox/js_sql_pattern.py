"""Plugin: JavaScript SQL Injection Pattern Detector (Phase 2, CRITICAL)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

SKIP_DIRS = ["node_modules", "venv", ".git", "dist", "build", "__pycache__", ".tox", "vendor"]
JS_EXTENSIONS = {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}

SQL_KEYWORDS = r'(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC)'

DANGEROUS_SQL_PATTERNS: list[tuple[str, re.Pattern]] = [
    # Template literal SQL: `SELECT ... ${var}`
    ("template literal SQL", re.compile(
        r'`[^`]*\b' + SQL_KEYWORDS + r'\b[^`]*\$\{',
        re.IGNORECASE,
    )),
    # String concat SQL: "SELECT..." + var  or  'SELECT...' + var
    ("string concat SQL", re.compile(
        r'["\'][^"\']*\b' + SQL_KEYWORDS + r'\b[^"\']*["\'][^;]*\+',
        re.IGNORECASE,
    )),
    # db.query / connection.query with concat or template arg
    ("db.query with concat", re.compile(
        r'\b(?:db|pool|connection|client|conn)\.(?:query|execute)\s*\([^)]*\+',
        re.IGNORECASE,
    )),
]


def _should_skip(path: Path) -> bool:
    return any(skip in path.parts for skip in SKIP_DIRS)


class JsSqlPatternPlugin(PluginBase):
    name = "js_sql_pattern"
    description = "Detect SQL injection patterns via string concatenation/template literals in JS/TS"
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
                for label, pat in DANGEROUS_SQL_PATTERNS:
                    if pat.search(line):
                        results.append(
                            Result(
                                plugin_name=self.name,
                                base_severity=Severity.CRITICAL,
                                title=f"SQL Injection Pattern (JS): {label}",
                                description=(
                                    f"Potential SQL injection via {label} in "
                                    f"'{src_file.relative_to(root)}' at line {lineno}."
                                ),
                                evidence=f"{src_file.relative_to(root)}:{lineno}: {line.strip()[:120]}",
                                recommendation=(
                                    "Use parameterized queries or a query builder. "
                                    "Never construct SQL with template literals or string concatenation."
                                ),
                                cwe_id="CWE-89",
                                rule_id="js_sql_injection",
                                endpoint=str(src_file),
                            )
                        )
                        break

        return results
