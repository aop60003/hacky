"""Plugin: PHP SQL Injection Pattern Detector (Phase 2, CRITICAL)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.file_utils import MAX_FILE_SIZE, should_skip
from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

# Patterns indicating string concatenation in SQL queries
SQL_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("mysql_query with string concat", re.compile(
        r'\bmysql_query\s*\(\s*["\'].*\$', re.IGNORECASE
    )),
    ("mysqli_query with string concat", re.compile(
        r'\bmysqli_query\s*\([^,]+,\s*["\'].*\$', re.IGNORECASE
    )),
    ("SQL string concat with variable", re.compile(
        r'["\'](?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b[^"\']*["\']\s*\.\s*\$',
        re.IGNORECASE
    )),
    ("query() with string concat", re.compile(
        r'->query\s*\(\s*["\'].*\$', re.IGNORECASE
    )),
]


class PhpSqlPatternPlugin(PluginBase):
    name = "php_sql_pattern"
    description = "Detect SQL injection patterns via string concatenation in PHP code"
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

        for src_file in root.rglob("*.php"):
            if not src_file.is_file() or should_skip(src_file):
                continue
            try:
                if src_file.stat().st_size > MAX_FILE_SIZE:
                    continue
                content = src_file.read_text(errors="ignore")
            except OSError:
                continue

            for lineno, line in enumerate(content.splitlines(), start=1):
                for label, pat in SQL_PATTERNS:
                    if pat.search(line):
                        results.append(
                            Result(
                                plugin_name=self.name,
                                base_severity=Severity.CRITICAL,
                                title=f"PHP SQL Injection Pattern: {label}",
                                description=(
                                    f"Potential SQL injection via string concatenation detected in "
                                    f"'{src_file.relative_to(root)}' at line {lineno}. "
                                    "User-controlled input may be injected into SQL queries."
                                ),
                                evidence=f"{src_file.relative_to(root)}:{lineno}: {line.strip()[:120]}",
                                recommendation=(
                                    "Use prepared statements (PDO or MySQLi) with parameterized queries "
                                    "instead of string concatenation."
                                ),
                                cwe_id="CWE-89",
                                rule_id="php_sql_injection",
                                endpoint=str(src_file),
                            )
                        )
                        break  # one result per line

        return results
