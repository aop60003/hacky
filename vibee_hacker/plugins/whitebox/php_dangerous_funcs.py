"""Plugin: PHP Dangerous Functions Detector (Phase 2, CRITICAL)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.file_utils import MAX_FILE_SIZE, should_skip
from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

# (label, pattern, cwe)
DANGEROUS_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("eval(", re.compile(r'\beval\s*\('), "CWE-78"),
    ("exec(", re.compile(r'\bexec\s*\('), "CWE-78"),
    ("system(", re.compile(r'\bsystem\s*\('), "CWE-78"),
    ("passthru(", re.compile(r'\bpassthru\s*\('), "CWE-78"),
    ("shell_exec(", re.compile(r'\bshell_exec\s*\('), "CWE-78"),
    ("preg_replace /e modifier", re.compile(r'\bpreg_replace\s*\(\s*[\'"][^\'"]*/e[\'"]'), "CWE-78"),
    ("unserialize(", re.compile(r'\bunserialize\s*\('), "CWE-78"),
    ("include($", re.compile(r'\b(?:include|require)(?:_once)?\s*\(\s*\$'), "CWE-78"),
    ("file_get_contents($", re.compile(r'\bfile_get_contents\s*\(\s*\$'), "CWE-78"),
    ("curl_exec(", re.compile(r'\bcurl_exec\s*\('), "CWE-78"),
]


class PhpDangerousFuncsPlugin(PluginBase):
    name = "php_dangerous_funcs"
    description = "Detect use of dangerous PHP functions (eval, exec, system, unserialize, etc.)"
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
                for label, pat, cwe in DANGEROUS_PATTERNS:
                    if pat.search(line):
                        results.append(
                            Result(
                                plugin_name=self.name,
                                base_severity=Severity.CRITICAL,
                                title=f"Dangerous PHP Function: {label}",
                                description=(
                                    f"Use of '{label}' detected in "
                                    f"'{src_file.relative_to(root)}' at line {lineno}. "
                                    "This can lead to remote code execution."
                                ),
                                evidence=f"{src_file.relative_to(root)}:{lineno}: {line.strip()[:120]}",
                                recommendation=(
                                    f"Avoid using {label}. Use safe alternatives or "
                                    "strictly validate and sanitize all inputs."
                                ),
                                cwe_id=cwe,
                                rule_id="php_dangerous_func",
                                endpoint=str(src_file),
                            )
                        )
                        break  # one result per line

        return results
