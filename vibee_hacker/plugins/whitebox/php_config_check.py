"""Plugin: PHP Insecure Configuration Detector (Phase 2, HIGH)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.file_utils import MAX_FILE_SIZE, should_skip
from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

# (label, pattern)
CONFIG_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("display_errors = On", re.compile(
        r'display_errors\s*=\s*On\b', re.IGNORECASE
    )),
    ("allow_url_include = On", re.compile(
        r'allow_url_include\s*=\s*On\b', re.IGNORECASE
    )),
    ("register_globals = On", re.compile(
        r'register_globals\s*=\s*On\b', re.IGNORECASE
    )),
    ("ini_set display_errors 1", re.compile(
        r"\bini_set\s*\(\s*['\"]display_errors['\"]\s*,\s*['\"]?1['\"]?\s*\)", re.IGNORECASE
    )),
    ("error_reporting(E_ALL)", re.compile(
        r'\berror_reporting\s*\(\s*E_ALL\s*\)', re.IGNORECASE
    )),
]

# Scan .php files AND php.ini files
EXTENSIONS = ("*.php", "*.ini")


class PhpConfigCheckPlugin(PluginBase):
    name = "php_config_check"
    description = "Detect insecure PHP configuration settings (display_errors, allow_url_include, etc.)"
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

        for pattern in EXTENSIONS:
            for src_file in root.rglob(pattern):
                if not src_file.is_file() or should_skip(src_file):
                    continue
                try:
                    if src_file.stat().st_size > MAX_FILE_SIZE:
                        continue
                    content = src_file.read_text(errors="ignore")
                except OSError:
                    continue

                for lineno, line in enumerate(content.splitlines(), start=1):
                    # Skip commented lines
                    stripped = line.strip()
                    if stripped.startswith(";") or stripped.startswith("#") or stripped.startswith("//"):
                        continue
                    for label, pat in CONFIG_PATTERNS:
                        if pat.search(line):
                            results.append(
                                Result(
                                    plugin_name=self.name,
                                    base_severity=Severity.HIGH,
                                    title=f"Insecure PHP Configuration: {label}",
                                    description=(
                                        f"Insecure PHP configuration '{label}' detected in "
                                        f"'{src_file.relative_to(root)}' at line {lineno}. "
                                        "This may expose sensitive error information or enable dangerous features."
                                    ),
                                    evidence=f"{src_file.relative_to(root)}:{lineno}: {line.strip()[:120]}",
                                    recommendation=(
                                        f"Disable '{label}' in production environments. "
                                        "Set display_errors = Off and log errors to a file instead."
                                    ),
                                    cwe_id="CWE-16",
                                    rule_id="php_insecure_config",
                                    endpoint=str(src_file),
                                )
                            )
                            break  # one result per line

        return results
