"""Plugin: Python Dangerous Functions Detector (Phase 2, CRITICAL)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

SKIP_DIRS = ["node_modules", "venv", ".git", "dist", "build", "__pycache__", ".tox", "vendor"]

# (label, pattern, cwe)
DANGEROUS_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("eval()", re.compile(r'\beval\s*\('), "CWE-94"),
    ("exec()", re.compile(r'\bexec\s*\('), "CWE-94"),
    ("pickle.loads()", re.compile(r'\bpickle\.loads\s*\('), "CWE-502"),
    ("shelve.open()", re.compile(r'\bshelve\.open\s*\('), "CWE-502"),
    ("marshal.loads()", re.compile(r'\bmarshal\.loads\s*\('), "CWE-502"),
    ("yaml.load() without SafeLoader", re.compile(r'\byaml\.load\s*\('), "CWE-94"),
    ("subprocess with shell=True", re.compile(r'\bsubprocess\.\w+\s*\([^)]*shell\s*=\s*True'), "CWE-78"),
    ("os.system()", re.compile(r'\bos\.system\s*\('), "CWE-78"),
    ("__import__()", re.compile(r'\b__import__\s*\('), "CWE-94"),
]


def _should_skip(path: Path) -> bool:
    return any(skip in path.parts for skip in SKIP_DIRS)


class PyDangerousFuncsPlugin(PluginBase):
    name = "py_dangerous_funcs"
    description = "Detect use of dangerous Python functions (eval, exec, pickle.loads, etc.)"
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

        for src_file in root.rglob("*.py"):
            if not src_file.is_file() or _should_skip(src_file):
                continue
            try:
                if src_file.stat().st_size > 5_000_000:
                    continue
                content = src_file.read_text(errors="ignore")
            except OSError:
                continue

            for lineno, line in enumerate(content.splitlines(), start=1):
                for label, pat, cwe in DANGEROUS_PATTERNS:
                    if pat.search(line):
                        # yaml.load with SafeLoader/FullLoader is safe — skip
                        if "yaml.load" in line and any(safe in line for safe in ("SafeLoader", "FullLoader", "safe_load")):
                            continue
                        results.append(
                            Result(
                                plugin_name=self.name,
                                base_severity=Severity.CRITICAL,
                                title=f"Dangerous Python Function: {label}",
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
                                rule_id="py_dangerous_func",
                                endpoint=str(src_file),
                            )
                        )
                        break  # one result per line

        return results
