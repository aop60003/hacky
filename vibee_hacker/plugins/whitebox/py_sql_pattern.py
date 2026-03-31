"""Plugin: Python SQL Injection Pattern Detector (Phase 2, CRITICAL)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.file_utils import MAX_FILE_SIZE, should_skip
from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

SQL_KEYWORDS = re.compile(r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC)\b', re.IGNORECASE)

# Patterns indicating dangerous SQL construction
DANGEROUS_SQL_PATTERNS: list[tuple[str, re.Pattern]] = [
    # f-string with SQL keyword: f"SELECT ... {var}"
    ("f-string SQL", re.compile(r'f["\'].*\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC)\b.*\{', re.IGNORECASE)),
    # % formatting with SQL: "SELECT ... " % var  or  "SELECT..." % (var,)
    ("%-format SQL", re.compile(r'["\'].*\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC)\b.*["\'].*%\s*[\w(]', re.IGNORECASE)),
    # .format() with SQL: "SELECT ...".format(
    (".format() SQL", re.compile(r'["\'].*\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC)\b.*["\']\.format\s*\(', re.IGNORECASE)),
    # string concat with SQL: "SELECT..." + var  or cursor.execute("SELECT..." + var)
    ("string concat SQL", re.compile(r'["\'].*\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC)\b.*["\']\s*\+', re.IGNORECASE)),
    # cursor.execute with concat or f-string in arg
    ("cursor.execute concat", re.compile(r'cursor\.execute\s*\(\s*["\'].*\+', re.IGNORECASE)),
]



class PySqlPatternPlugin(PluginBase):
    name = "py_sql_pattern"
    description = "Detect SQL injection patterns via string formatting in Python code"
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

        for src_file in root.rglob("*.py"):
            if not src_file.is_file() or should_skip(src_file):
                continue
            try:
                if src_file.stat().st_size > MAX_FILE_SIZE:
                    continue
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
                                title=f"SQL Injection Pattern: {label}",
                                description=(
                                    f"Potential SQL injection via {label} in "
                                    f"'{src_file.relative_to(root)}' at line {lineno}."
                                ),
                                evidence=f"{src_file.relative_to(root)}:{lineno}: {line.strip()[:120]}",
                                recommendation=(
                                    "Use parameterized queries or an ORM. "
                                    "Never construct SQL with user-controlled input."
                                ),
                                cwe_id="CWE-89",
                                rule_id="py_sql_injection",
                                endpoint=str(src_file),
                            )
                        )
                        break

        return results
