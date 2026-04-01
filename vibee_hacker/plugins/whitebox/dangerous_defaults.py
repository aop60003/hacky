"""Plugin 6: Dangerous Configuration Defaults Detector (Phase 2, HIGH)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

SKIP_DIRS = ["node_modules", "venv", ".git", "dist", "build", "__pycache__", ".tox", "vendor"]

DANGEROUS_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    (
        "DEBUG mode enabled",
        re.compile(r'(?i)\bDEBUG\s*[=:]\s*(True|true|1|yes)\b'),
        "Debug mode exposes stack traces and internal details to users.",
    ),
    (
        "Wildcard ALLOWED_HOSTS",
        re.compile(r"ALLOWED_HOSTS\s*=\s*\[[\s'\"\*]+\]"),
        "Wildcard ALLOWED_HOSTS allows HTTP Host header attacks.",
    ),
    (
        "CORS allow all origins",
        re.compile(r'(?i)CORS_ALLOW_ALL\s*[=:]\s*(True|true|1)'),
        "Allowing all CORS origins disables cross-origin protection.",
    ),
    (
        "Default/weak SECRET_KEY",
        re.compile(r'SECRET_KEY\s*=\s*["\'](?:django-insecure|secret|changeme|your-secret-key|supersecret)[^"\']*["\']', re.IGNORECASE),
        "A weak or default SECRET_KEY compromises session security.",
    ),
    (
        "CORS all origins wildcard",
        re.compile(r'(?i)Access-Control-Allow-Origin["\s:]*\*'),
        "Wildcard CORS header allows any origin to read responses.",
    ),
]


def _should_skip(path: Path) -> bool:
    return any(skip in path.parts for skip in SKIP_DIRS)


class DangerousDefaultsPlugin(PluginBase):
    name = "dangerous_defaults"
    description = "Detect dangerous configuration defaults like DEBUG=True or wildcard CORS"
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

        for src_file in root.rglob("*"):
            if not src_file.is_file() or _should_skip(src_file):
                continue
            if src_file.suffix.lower() in (".png", ".jpg", ".jpeg", ".gif", ".ico", ".bin", ".exe", ".pyc"):
                continue
            try:
                content = src_file.read_text(errors="ignore")
            except OSError:
                continue

            for lineno, line in enumerate(content.splitlines(), start=1):
                for label, pat, rationale in DANGEROUS_PATTERNS:
                    if pat.search(line):
                        results.append(
                            Result(
                                plugin_name=self.name,
                                base_severity=Severity.HIGH,
                                title=f"Dangerous Default Detected: {label}",
                                description=(
                                    f"{rationale} Found in "
                                    f"'{src_file.relative_to(root)}' at line {lineno}."
                                ),
                                evidence=f"{src_file.relative_to(root)}:{lineno}: {line.strip()[:120]}",
                                recommendation=(
                                    f"Fix '{label}': disable debug mode in production, restrict allowed hosts, "
                                    "and use strong, randomly-generated secret keys."
                                ),
                                cwe_id="CWE-1188",
                                rule_id="dangerous_default",
                                endpoint=str(src_file),
                            )
                        )

        return results
