"""Plugin: Java Dangerous Functions Detector (Phase 2, CRITICAL)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.file_utils import MAX_FILE_SIZE, should_skip
from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

# (label, pattern, cwe)
DANGEROUS_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("Runtime.exec(", re.compile(r'\bRuntime\b.*\.exec\s*\('), "CWE-78"),
    ("ProcessBuilder(", re.compile(r'\bnew\s+ProcessBuilder\s*\('), "CWE-78"),
    ("ObjectInputStream.readObject()", re.compile(r'\breadObject\s*\(\s*\)'), "CWE-502"),
    ("ScriptEngine.eval(", re.compile(r'\bScriptEngine\b.*\.eval\s*\('), "CWE-94"),
    ("XStream()", re.compile(r'\bnew\s+XStream\s*\('), "CWE-502"),
    ("new SnakeYaml()", re.compile(r'\bnew\s+Yaml\s*\(\s*\)'), "CWE-502"),
]


class JavaDangerousFuncsPlugin(PluginBase):
    name = "java_dangerous_funcs"
    description = "Detect use of dangerous Java functions (Runtime.exec, ObjectInputStream, XStream, etc.)"
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

        for src_file in root.rglob("*.java"):
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
                                title=f"Dangerous Java Function: {label}",
                                description=(
                                    f"Use of '{label}' detected in "
                                    f"'{src_file.relative_to(root)}' at line {lineno}. "
                                    "This can lead to remote code execution or deserialization attacks."
                                ),
                                evidence=f"{src_file.relative_to(root)}:{lineno}: {line.strip()[:120]}",
                                recommendation=(
                                    f"Avoid using {label}. Use safe alternatives or "
                                    "strictly validate and sanitize all inputs."
                                ),
                                cwe_id=cwe,
                                rule_id="java_dangerous_func",
                                endpoint=str(src_file),
                            )
                        )
                        break  # one result per line

        return results
