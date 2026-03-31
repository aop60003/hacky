"""Plugin: Java SQL Injection Pattern Detector (Phase 2, CRITICAL)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.file_utils import MAX_FILE_SIZE, should_skip
from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

# Patterns indicating raw SQL string concatenation (NOT PreparedStatement)
SQL_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("Statement.execute with concat", re.compile(
        r'\bstmt(?:\.execute|\.executeQuery|\.executeUpdate)\s*\(\s*["\'].*\+',
        re.IGNORECASE
    )),
    ("execute() with SQL concat", re.compile(
        r'\.execute(?:Query|Update)?\s*\(\s*["\'](?:SELECT|INSERT|UPDATE|DELETE)[^"\']*["\']\s*\+',
        re.IGNORECASE
    )),
    ("createStatement().execute with concat", re.compile(
        r'createStatement\s*\(\s*\)\.execute\w*\s*\(\s*["\'].*\+',
        re.IGNORECASE
    )),
    ("SQL string build with concat", re.compile(
        r'["\'](?:SELECT|INSERT|UPDATE|DELETE)\s+.*["\']\s*\+\s*\w',
        re.IGNORECASE
    )),
]


class JavaSqlPatternPlugin(PluginBase):
    name = "java_sql_pattern"
    description = "Detect SQL injection patterns via string concatenation in Java code"
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

        for src_file in root.rglob("*.java"):
            if not src_file.is_file() or should_skip(src_file):
                continue
            try:
                if src_file.stat().st_size > MAX_FILE_SIZE:
                    continue
                content = src_file.read_text(errors="ignore")
            except OSError:
                continue

            # Skip files that only use PreparedStatement (no Statement)
            for lineno, line in enumerate(content.splitlines(), start=1):
                # Skip lines that reference PreparedStatement
                if "PreparedStatement" in line or "prepareStatement" in line:
                    continue
                for label, pat in SQL_PATTERNS:
                    if pat.search(line):
                        results.append(
                            Result(
                                plugin_name=self.name,
                                base_severity=Severity.CRITICAL,
                                title=f"Java SQL Injection Pattern: {label}",
                                description=(
                                    f"Potential SQL injection via string concatenation detected in "
                                    f"'{src_file.relative_to(root)}' at line {lineno}. "
                                    "User-controlled input may be injected into SQL queries."
                                ),
                                evidence=f"{src_file.relative_to(root)}:{lineno}: {line.strip()[:120]}",
                                recommendation=(
                                    "Use PreparedStatement with parameterized queries "
                                    "instead of string concatenation."
                                ),
                                cwe_id="CWE-89",
                                rule_id="java_sql_injection",
                                endpoint=str(src_file),
                            )
                        )
                        break  # one result per line

        return results
