"""TypeScript/React security pattern detection."""

import os
import re

from vibee_hacker.core.plugin_base import PluginBase
from vibee_hacker.core.models import Result, Severity, Target

TS_PATTERNS = [
    (r'dangerouslySetInnerHTML\s*=', "React dangerouslySetInnerHTML (XSS)", Severity.HIGH, "CWE-79"),
    (r'eval\s*\(', "eval() usage", Severity.HIGH, "CWE-95"),
    (r'document\.write\s*\(', "document.write (DOM XSS)", Severity.HIGH, "CWE-79"),
    (r'\.innerHTML\s*=', "innerHTML assignment (XSS)", Severity.MEDIUM, "CWE-79"),
    (r'child_process\s*\.\s*(exec|spawn)\s*\(', "Command execution", Severity.CRITICAL, "CWE-78"),
    (r'new\s+Function\s*\(', "Dynamic function creation", Severity.HIGH, "CWE-95"),
    (r'process\.env\.[A-Z_]+.*(?:password|secret|key|token)', "Env secret usage without validation", Severity.MEDIUM, "CWE-798"),
    (r'(?:any|Object)\s*(?:as|:)', "Unsafe type assertion (any)", Severity.LOW, "CWE-704"),
    (r'@ts-ignore', "@ts-ignore suppression", Severity.LOW, "CWE-710"),
    (r'require\s*\(\s*[^\'\"]+\)', "Dynamic require (injection risk)", Severity.MEDIUM, "CWE-94"),
]


class TsPatternsPlugin(PluginBase):
    name = "ts_patterns"
    description = "TypeScript/React security pattern detection"
    category = "whitebox"
    phase = 2

    def is_applicable(self, target: Target) -> bool:
        return bool(target.path)

    async def run(self, target: Target, context=None) -> list[Result]:
        if not target.path:
            return []
        results = []
        for root, dirs, files in os.walk(target.path):
            dirs[:] = [d for d in dirs if d not in ("node_modules", ".next", "dist", "build")]
            for f in files:
                if f.endswith((".ts", ".tsx")):
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
            for pattern, title, severity, cwe in TS_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    results.append(Result(
                        plugin_name=self.name,
                        base_severity=severity,
                        title=f"TS: {title}",
                        description=f"Found in {filepath}:{i}: {line.strip()[:100]}",
                        endpoint=filepath,
                        rule_id=f"ts_{re.sub(r'[^a-z0-9]', '_', title.lower())[:40]}",
                        cwe_id=cwe,
                        recommendation=f"Review and fix: {title}",
                    ))
                    break  # One finding per line
        return results
