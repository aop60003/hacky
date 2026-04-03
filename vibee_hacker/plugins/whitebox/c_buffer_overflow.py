"""Plugin: C Buffer Overflow Detection (whitebox)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.file_utils import iter_files, safe_read, should_skip
from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

# Unsafe C functions: pattern -> (title, cwe_id, recommendation)
UNSAFE_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (
        re.compile(r'\bstrcpy\s*\('),
        "Unsafe strcpy() usage",
        "CWE-120",
        "Replace strcpy() with strncpy() or strlcpy() to enforce buffer bounds.",
    ),
    (
        re.compile(r'\bgets\s*\('),
        "Unsafe gets() usage",
        "CWE-120",
        "Replace gets() with fgets() which requires a buffer size argument.",
    ),
    (
        re.compile(r'\bsprintf\s*\('),
        "Unsafe sprintf() usage",
        "CWE-120",
        "Replace sprintf() with snprintf() to enforce buffer size limits.",
    ),
    (
        re.compile(r'\bscanf\s*\(\s*"[^"]*%s'),
        "Unsafe scanf() with %s format",
        "CWE-120",
        "Use scanf() with width specifier (e.g. %255s) or fgets() instead.",
    ),
    (
        re.compile(r'\bstrcat\s*\('),
        "Unsafe strcat() usage",
        "CWE-120",
        "Replace strcat() with strncat() or strlcat() to enforce buffer bounds.",
    ),
]


class CBufferOverflowPlugin(PluginBase):
    name = "c_buffer_overflow"
    description = "Detect unsafe C/C++ functions susceptible to buffer overflow (CWE-120)"
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

        for src_file in iter_files(root, {".c", ".h", ".cpp", ".cc", ".cxx"}):
            content = safe_read(src_file)
            if content is None:
                continue

            for lineno, line in enumerate(content.splitlines(), start=1):
                # Skip commented lines
                stripped = line.lstrip()
                if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
                    continue

                for pattern, title, cwe_id, recommendation in UNSAFE_PATTERNS:
                    if pattern.search(line):
                        results.append(
                            Result(
                                plugin_name=self.name,
                                base_severity=Severity.HIGH,
                                title=title,
                                description=(
                                    f"Unsafe buffer operation found in "
                                    f"'{src_file.relative_to(root)}' at line {lineno}. "
                                    "This function does not enforce bounds checking and may "
                                    "allow buffer overflow attacks."
                                ),
                                evidence=f"{src_file.relative_to(root)}:{lineno}: {line.strip()[:120]}",
                                recommendation=recommendation,
                                cwe_id=cwe_id,
                                rule_id="c_buffer_overflow",
                                endpoint=str(src_file),
                            )
                        )
                        break  # one finding per line

        return results
