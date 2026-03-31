"""Plugin: Node.js Security Checker (Phase 2, HIGH)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

SKIP_DIRS = ["node_modules", "venv", ".git", "dist", "build", "__pycache__", ".tox", "vendor"]
JS_EXTENSIONS = {".js", ".ts", ".mjs", ".cjs"}

NODE_PATTERNS: list[tuple[str, re.Pattern, str, str]] = [
    (
        "child_process.exec with variable",
        re.compile(r'\bexec\s*\(\s*(?!["\'])'),
        "js_node_exec",
        "CWE-78",
    ),
    (
        "CORS origin: '*'",
        re.compile(r'\borigin\s*:\s*["\'][*]["\']'),
        "js_node_cors_wildcard",
        "CWE-346",
    ),
    (
        "Object.assign with user input",
        re.compile(r'\bObject\.assign\s*\(\s*\{\s*\}'),
        "js_node_object_assign",
        "CWE-915",
    ),
    (
        "lodash.merge with user input",
        re.compile(r'\b(?:_\.merge|lodash\.merge|merge)\s*\('),
        "js_node_lodash_merge",
        "CWE-915",
    ),
]

# child_process exec check - only flag if 'child_process' or 'exec' is imported
EXEC_IMPORT_PATTERN = re.compile(r'require\s*\(\s*["\']child_process["\']|from\s+["\']child_process["\']')


def _should_skip(path: Path) -> bool:
    return any(skip in path.parts for skip in SKIP_DIRS)


class JsNodeCheckPlugin(PluginBase):
    name = "js_node_check"
    description = "Detect Node.js security issues (child_process.exec, CORS wildcard, prototype pollution, etc.)"
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
            if not src_file.is_file() or src_file.suffix.lower() not in JS_EXTENSIONS:
                continue
            if _should_skip(src_file):
                continue
            try:
                content = src_file.read_text(errors="ignore")
            except OSError:
                continue

            has_child_process = EXEC_IMPORT_PATTERN.search(content) is not None

            for lineno, line in enumerate(content.splitlines(), start=1):
                for label, pat, rule_id, cwe in NODE_PATTERNS:
                    if pat.search(line):
                        # For exec pattern, only flag if child_process is imported
                        if rule_id == "js_node_exec" and not has_child_process:
                            continue
                        results.append(
                            Result(
                                plugin_name=self.name,
                                base_severity=Severity.HIGH,
                                title=f"Node.js Security Issue: {label}",
                                description=(
                                    f"Node.js security misconfiguration '{label}' detected in "
                                    f"'{src_file.relative_to(root)}' at line {lineno}."
                                ),
                                evidence=f"{src_file.relative_to(root)}:{lineno}: {line.strip()[:120]}",
                                recommendation=(
                                    f"Address the Node.js security issue: {label}. "
                                    "Use execFile instead of exec, restrict CORS origins, "
                                    "and avoid Object.assign/merge with user-controlled objects."
                                ),
                                cwe_id=cwe,
                                rule_id=rule_id,
                                endpoint=str(src_file),
                            )
                        )
                        break

        return results
