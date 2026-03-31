"""Plugin: Java Spring Security Misconfiguration Detector (Phase 2, HIGH)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.file_utils import MAX_FILE_SIZE, should_skip
from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

# (label, pattern, rule_suffix)
SPRING_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("csrf().disable()", re.compile(
        r'\.csrf\s*\(\s*\)\s*\.disable\s*\(\s*\)'
    ), "java_spring_csrf_disabled"),
    ("csrf(csrf -> csrf.disable())", re.compile(
        r'\.csrf\s*\(\s*\w+\s*->\s*\w+\.disable\s*\(\s*\)\s*\)'
    ), "java_spring_csrf_disabled"),
    ("@CrossOrigin(\"*\")", re.compile(
        r'@CrossOrigin\s*\(\s*["\'][*]["\']'
    ), "java_spring_cors_wildcard"),
    ("management.endpoints.web.exposure.include=*", re.compile(
        r'management\.endpoints\.web\.exposure\.include\s*=\s*\*'
    ), "java_spring_actuator_exposed"),
]


class JavaSpringCheckPlugin(PluginBase):
    name = "java_spring_check"
    description = "Detect Spring Security misconfigurations (CSRF disabled, wildcard CORS, exposed actuators)"
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

        for ext in ("*.java", "*.properties", "*.yml", "*.yaml"):
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
                    stripped = line.strip()
                    # Skip comments
                    if stripped.startswith("//") or stripped.startswith("#"):
                        continue
                    for label, pat, rule_suffix in SPRING_PATTERNS:
                        if pat.search(line):
                            results.append(
                                Result(
                                    plugin_name=self.name,
                                    base_severity=Severity.HIGH,
                                    title=f"Spring Security Misconfiguration: {label}",
                                    description=(
                                        f"Insecure Spring configuration '{label}' detected in "
                                        f"'{src_file.relative_to(root)}' at line {lineno}. "
                                        "This may expose the application to CSRF, CORS, or management endpoint attacks."
                                    ),
                                    evidence=f"{src_file.relative_to(root)}:{lineno}: {line.strip()[:120]}",
                                    recommendation=(
                                        f"Review and fix the Spring Security configuration for '{label}'. "
                                        "Enable CSRF protection, restrict CORS origins, and secure actuator endpoints."
                                    ),
                                    cwe_id="CWE-16",
                                    rule_id=rule_suffix,
                                    endpoint=str(src_file),
                                )
                            )
                            break  # one result per line

        return results
