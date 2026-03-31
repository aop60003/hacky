"""Plugin: Python SSRF Pattern Detector (Phase 2, CRITICAL)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

SKIP_DIRS = ["node_modules", "venv", ".git", "dist", "build", "__pycache__", ".tox", "vendor"]

# Match HTTP client calls where the first argument is NOT a string literal
# i.e., it's a variable. Pattern: requests.get(something) where 'something' doesn't start with " or '
HTTP_CALL_PATTERN = re.compile(
    r'\b(?:requests|httpx|urllib\.request)\.'
    r'(?:get|post|put|delete|patch|head|request|urlopen)\s*\('
    r'\s*([^"\'\s][^,)]*)',  # first arg is not a string literal
)

# String literal starters – if the arg starts with these, it's a literal (safe)
STRING_LITERAL_PATTERN = re.compile(r'^["\']|^[brBR]*["\']|^f["\']')


def _should_skip(path: Path) -> bool:
    return any(skip in path.parts for skip in SKIP_DIRS)


class PySsrfPatternPlugin(PluginBase):
    name = "py_ssrf_pattern"
    description = "Detect potential SSRF patterns where HTTP clients are called with variable URLs"
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
                content = src_file.read_text(errors="ignore")
            except OSError:
                continue

            for lineno, line in enumerate(content.splitlines(), start=1):
                match = HTTP_CALL_PATTERN.search(line)
                if match:
                    first_arg = match.group(1).strip()
                    # Skip if the argument is a string literal
                    if STRING_LITERAL_PATTERN.match(first_arg):
                        continue
                    results.append(
                        Result(
                            plugin_name=self.name,
                            base_severity=Severity.CRITICAL,
                            title="Potential SSRF: HTTP Client Called with Variable URL",
                            description=(
                                f"An HTTP client function is called with a non-literal URL argument in "
                                f"'{src_file.relative_to(root)}' at line {lineno}. "
                                "If the URL is user-controlled, this is an SSRF vulnerability."
                            ),
                            evidence=f"{src_file.relative_to(root)}:{lineno}: {line.strip()[:120]}",
                            recommendation=(
                                "Validate and allowlist URLs before making outbound HTTP requests. "
                                "Never pass raw user input to HTTP client functions."
                            ),
                            cwe_id="CWE-918",
                            rule_id="py_ssrf_pattern",
                            endpoint=str(src_file),
                        )
                    )

        return results
