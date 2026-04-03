"""Rust security pattern detection."""

import os
import re

from vibee_hacker.core.plugin_base import PluginBase
from vibee_hacker.core.models import Result, Severity, Target

RUST_PATTERNS = [
    (r'unsafe\s*\{', "Unsafe block usage", Severity.MEDIUM, "CWE-676"),
    (r'\.unwrap\(\)', "Unwrap without error handling", Severity.LOW, "CWE-252"),
    (r'std::process::Command::new', "Process command execution", Severity.HIGH, "CWE-78"),
    (r'std::fs::.*permissions.*0o777', "World-writable permissions", Severity.HIGH, "CWE-732"),
    (r'panic!\s*\(', "Explicit panic (DoS risk)", Severity.LOW, "CWE-248"),
    (r'#\[allow\(unsafe_code\)\]', "Unsafe code explicitly allowed", Severity.MEDIUM, "CWE-676"),
    (r'transmute\s*[:<(]', "Memory transmutation (type safety bypass)", Severity.HIGH, "CWE-843"),
    (r'from_raw_parts', "Raw pointer dereference", Severity.HIGH, "CWE-119"),
    (r'format!\s*\(.*\{.*\}.*\)', "Format string (check for user input)", Severity.LOW, "CWE-134"),
]


class RustPatternsPlugin(PluginBase):
    name = "rust_patterns"
    description = "Rust security pattern detection"
    category = "whitebox"
    phase = 2

    def is_applicable(self, target: Target) -> bool:
        return bool(target.path)

    async def run(self, target: Target, context=None) -> list[Result]:
        if not target.path:
            return []
        results = []
        for root, dirs, files in os.walk(target.path):
            dirs[:] = [d for d in dirs if d not in ("target", ".cargo")]
            for f in files:
                if f.endswith(".rs"):
                    filepath = os.path.join(root, f)
                    results.extend(self._scan_file(filepath))
                    if len(results) >= 50:
                        return results[:50]
        return results

    def _scan_file(self, filepath: str) -> list[Result]:
        results = []
        try:
            with open(filepath, encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except OSError:
            return []

        for i, line in enumerate(lines, 1):
            for pattern, title, severity, cwe in RUST_PATTERNS:
                if re.search(pattern, line):
                    results.append(Result(
                        plugin_name=self.name,
                        base_severity=severity,
                        title=f"Rust: {title}",
                        description=f"Found in {filepath}:{i}: {line.strip()[:100]}",
                        endpoint=filepath,
                        rule_id=f"rust_{re.sub(r'[^a-z0-9]', '_', title.lower())[:40]}",
                        cwe_id=cwe,
                        recommendation=f"Review and fix: {title}",
                    ))
                    break
        return results
