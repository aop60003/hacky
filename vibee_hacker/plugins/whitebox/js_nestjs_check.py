"""Plugin: NestJS Security Checker (Phase 2, HIGH)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

SKIP_DIRS = ["node_modules", "venv", ".git", "dist", "build", "__pycache__", ".tox", "vendor"]
TS_EXTENSIONS = {".ts"}

# Detect @Controller decorator
CONTROLLER_PATTERN = re.compile(r'@Controller\s*\(')
# Detect @UseGuards decorator
USE_GUARDS_PATTERN = re.compile(r'@UseGuards\s*\(')
# Detect @Public decorator (overuse)
PUBLIC_PATTERN = re.compile(r'@Public\s*\(\s*\)')


def _should_skip(path: Path) -> bool:
    return any(skip in path.parts for skip in SKIP_DIRS)


def _find_controller_blocks(content: str) -> list[tuple[int, str]]:
    """Find (lineno, block_text) for each @Controller decorated class."""
    lines = content.splitlines()
    blocks = []
    i = 0
    while i < len(lines):
        if CONTROLLER_PATTERN.search(lines[i]):
            # Grab context: from the line before decorator to ~50 lines after
            start = max(0, i - 5)
            end = min(len(lines), i + 50)
            block = "\n".join(lines[start:end])
            blocks.append((i + 1, block))
        i += 1
    return blocks


class JsNestjsCheckPlugin(PluginBase):
    name = "js_nestjs_check"
    description = "Detect NestJS security issues (controllers without guards, missing ValidationPipe, etc.)"
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
            if not src_file.is_file() or src_file.suffix.lower() not in TS_EXTENSIONS:
                continue
            if _should_skip(src_file):
                continue
            try:
                content = src_file.read_text(errors="ignore")
            except OSError:
                continue

            # Check for @Controller without @UseGuards in the same file
            if CONTROLLER_PATTERN.search(content) and not USE_GUARDS_PATTERN.search(content):
                # Find the line number of first @Controller
                for lineno, line in enumerate(content.splitlines(), start=1):
                    if CONTROLLER_PATTERN.search(line):
                        results.append(
                            Result(
                                plugin_name=self.name,
                                base_severity=Severity.HIGH,
                                title="NestJS Controller Without @UseGuards",
                                description=(
                                    f"A NestJS @Controller in '{src_file.relative_to(root)}' at line {lineno} "
                                    "does not use @UseGuards. Routes may be unprotected."
                                ),
                                evidence=f"{src_file.relative_to(root)}:{lineno}: {line.strip()[:120]}",
                                recommendation=(
                                    "Apply @UseGuards(AuthGuard) or appropriate guards to all controllers. "
                                    "Use global guards where appropriate."
                                ),
                                cwe_id="CWE-862",
                                rule_id="js_nestjs_no_guard",
                                endpoint=str(src_file),
                            )
                        )
                        break  # one result per file

        return results
