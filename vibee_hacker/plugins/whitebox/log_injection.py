"""Plugin 10: Log Injection Detector (Phase 2, MEDIUM)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

SKIP_DIRS = ["node_modules", "venv", ".git", "dist", "build", "__pycache__", ".tox", "vendor"]

# Python log injection patterns: user-controlled data in log calls
PY_LOG_PATTERNS: list[tuple[str, re.Pattern]] = [
    (
        "User input in Python logger (f-string)",
        re.compile(
            r'(?:logger|logging)\s*\.\s*(?:debug|info|warning|error|critical|exception)\s*\('
            r'\s*f["\'].*?(?:request\.|req\.|user_input|user_data|username|email|body|args|params|query)',
            re.IGNORECASE,
        ),
    ),
    (
        "User input directly passed to Python logger",
        re.compile(
            r'(?:logger|logging)\s*\.\s*(?:debug|info|warning|error|critical|exception)\s*\('
            r'\s*(?:request\.|req\.|user_input|user_data|message|body|args|params|data)',
            re.IGNORECASE,
        ),
    ),
    (
        "User input in Python logger (% format)",
        re.compile(
            r'(?:logger|logging)\s*\.\s*(?:debug|info|warning|error|critical|exception)\s*\('
            r'\s*["\'][^"\']*%[sd][^"\']*["\'][^,)]*,\s*(?:request\.|req\.|user_input|user_data)',
            re.IGNORECASE,
        ),
    ),
]

# JavaScript log injection patterns
JS_LOG_PATTERNS: list[tuple[str, re.Pattern]] = [
    (
        "User input in console.log",
        re.compile(
            r'console\s*\.\s*(?:log|warn|error|info)\s*\('
            r'.*?(?:req\.body|req\.query|req\.params|req\.headers|request\.body)',
            re.IGNORECASE,
        ),
    ),
    (
        "User input in JS logger",
        re.compile(
            r'(?:logger|winston|bunyan|pino)\s*\.\s*(?:debug|info|warn|error)\s*\('
            r'.*?(?:req\.body|req\.query|req\.params)',
            re.IGNORECASE,
        ),
    ),
]

PY_EXTENSIONS = {".py"}
JS_EXTENSIONS = {".js", ".ts", ".jsx", ".tsx"}


def _should_skip(path: Path) -> bool:
    return any(skip in path.parts for skip in SKIP_DIRS)


class LogInjectionPlugin(PluginBase):
    name = "log_injection"
    description = "Detect user-controlled input passed directly to logging statements"
    category = "whitebox"
    phase = 2
    base_severity = Severity.MEDIUM

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.path:
            return []

        root = Path(target.path)
        if not root.exists():
            return []

        results: list[Result] = []

        for src_file in root.rglob("*"):
            if not src_file.is_file() or _should_skip(src_file):
                continue
            ext = src_file.suffix.lower()
            if ext not in (PY_EXTENSIONS | JS_EXTENSIONS):
                continue
            try:
                content = src_file.read_text(errors="ignore")
            except OSError:
                continue

            patterns = PY_LOG_PATTERNS if ext in PY_EXTENSIONS else JS_LOG_PATTERNS

            for lineno, line in enumerate(content.splitlines(), start=1):
                stripped = line.strip()
                if stripped.startswith("#") or stripped.startswith("//"):
                    continue

                for label, pat in patterns:
                    if pat.search(line):
                        results.append(
                            Result(
                                plugin_name=self.name,
                                base_severity=Severity.MEDIUM,
                                title=f"Log Injection Risk: {label}",
                                description=(
                                    f"User-controlled data appears to be logged without sanitization in "
                                    f"'{src_file.relative_to(root)}' at line {lineno}. "
                                    "Attackers can inject fake log entries or exploit log parsers."
                                ),
                                evidence=f"{src_file.relative_to(root)}:{lineno}: {line.strip()[:120]}",
                                recommendation=(
                                    "Sanitize or encode user input before logging. "
                                    "Replace newlines (\\n, \\r) and other control characters. "
                                    "Use structured logging with separate fields for user data."
                                ),
                                cwe_id="CWE-117",
                                rule_id="log_injection",
                                endpoint=str(src_file),
                            )
                        )
                        break

        return results
