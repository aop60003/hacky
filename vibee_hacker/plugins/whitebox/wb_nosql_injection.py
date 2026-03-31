"""Plugin: NoSQL Injection Pattern Detector (Phase 2, CRITICAL)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.file_utils import MAX_FILE_SIZE, should_skip
from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

# (label, pattern)
NOSQL_PATTERNS: list[tuple[str, re.Pattern]] = [
    ('$gt operator in query', re.compile(r'["\$]gt["\']?\s*["\']?\s*:')),
    ('$ne operator in query', re.compile(r'["\$]ne["\']?\s*["\']?\s*:')),
    ('$where operator in query', re.compile(r'["\$]where["\']?\s*["\']?\s*:')),
    ('$lt operator in query', re.compile(r'["\$]lt["\']?\s*["\']?\s*:')),
    ('$in operator with user input', re.compile(r'["\$]in["\']?\s*["\']?\s*:\s*\w')),
    ('collection.find(userInput)', re.compile(
        r'\bcollection\.find\s*\(\s*(?!{)[a-zA-Z_]\w*\s*\)'
    )),
    ('MongoDB operator injection', re.compile(
        r'["\'][{]?\s*["\$]\$(?:gt|lt|ne|gte|lte|in|nin|where|regex|exists)["\']'
    )),
]

EXTENSIONS = ("*.py", "*.js", "*.ts")


class WbNoSqlInjectionPlugin(PluginBase):
    name = "wb_nosql_injection"
    description = "Detect NoSQL injection patterns ($gt, $ne, $where, etc.) in Python/JS/TS code"
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

        for ext in EXTENSIONS:
            for src_file in root.rglob(ext):
                if not src_file.is_file() or should_skip(src_file):
                    continue
                try:
                    if src_file.stat().st_size > MAX_FILE_SIZE:
                        continue
                    content = src_file.read_text(errors="ignore")
                except OSError:
                    continue

                for lineno, line in enumerate(content.splitlines(), start=1):
                    for label, pat in NOSQL_PATTERNS:
                        if pat.search(line):
                            results.append(
                                Result(
                                    plugin_name=self.name,
                                    base_severity=Severity.CRITICAL,
                                    title=f"NoSQL Injection Pattern: {label}",
                                    description=(
                                        f"Potential NoSQL injection pattern '{label}' detected in "
                                        f"'{src_file.relative_to(root)}' at line {lineno}. "
                                        "MongoDB operators in user-controlled input can bypass authentication."
                                    ),
                                    evidence=f"{src_file.relative_to(root)}:{lineno}: {line.strip()[:120]}",
                                    recommendation=(
                                        "Validate and sanitize all user inputs before using them in NoSQL queries. "
                                        "Use schema validation (e.g., Mongoose) and reject input containing MongoDB operators."
                                    ),
                                    cwe_id="CWE-943",
                                    rule_id="wb_nosql_injection",
                                    endpoint=str(src_file),
                                )
                            )
                            break  # one result per line

        return results
