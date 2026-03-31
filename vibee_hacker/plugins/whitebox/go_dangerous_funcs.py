"""Plugin: Go Dangerous Functions Detector (Phase 2, CRITICAL)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.file_utils import MAX_FILE_SIZE, should_skip
from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

DANGEROUS_PATTERNS_FIXED: list[tuple[str, re.Pattern, str]] = [
    ("exec.Command()", re.compile(r'\bexec\.Command\s*\('), "CWE-78"),
    ("text/template (unsafe HTML)", re.compile(r'"text/template"'), "CWE-79"),
    ("sql.Query/Exec with fmt.Sprintf", re.compile(
        r'\bdb\.(?:Query|Exec|QueryRow)\s*\(\s*fmt\.Sprintf'
    ), "CWE-89"),
    ("http.ListenAndServe (no TLS)", re.compile(
        r'\bhttp\.ListenAndServe\s*\('
    ), "CWE-319"),
]


class GoDangerousFuncsPlugin(PluginBase):
    name = "go_dangerous_funcs"
    description = "Detect use of dangerous Go functions (exec.Command, text/template, http without TLS, etc.)"
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

        for src_file in root.rglob("*.go"):
            if not src_file.is_file() or should_skip(src_file):
                continue
            try:
                if src_file.stat().st_size > MAX_FILE_SIZE:
                    continue
                content = src_file.read_text(errors="ignore")
            except OSError:
                continue

            for lineno, line in enumerate(content.splitlines(), start=1):
                for label, pat, cwe in DANGEROUS_PATTERNS_FIXED:
                    if pat.search(line):
                        results.append(
                            Result(
                                plugin_name=self.name,
                                base_severity=Severity.CRITICAL,
                                title=f"Dangerous Go Function: {label}",
                                description=(
                                    f"Use of '{label}' detected in "
                                    f"'{src_file.relative_to(root)}' at line {lineno}. "
                                    "This may lead to command injection, XSS, SQL injection, or insecure transport."
                                ),
                                evidence=f"{src_file.relative_to(root)}:{lineno}: {line.strip()[:120]}",
                                recommendation=(
                                    f"Avoid using {label} with user-controlled input. "
                                    "Use html/template instead of text/template, parameterized queries, and TLS."
                                ),
                                cwe_id=cwe,
                                rule_id="go_dangerous_func",
                                endpoint=str(src_file),
                            )
                        )
                        break  # one result per line

        return results
