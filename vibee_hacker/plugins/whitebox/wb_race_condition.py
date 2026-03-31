"""Plugin: Race Condition / TOCTOU Pattern Detector (Phase 2, MEDIUM)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.file_utils import MAX_FILE_SIZE, should_skip
from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

# Individual line-level patterns for TOCTOU indicators
RACE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("os.path.exists() check (TOCTOU risk)", re.compile(r'\bos\.path\.exists\s*\(')),
    ("fs.existsSync() check (TOCTOU risk)", re.compile(r'\bfs\.existsSync\s*\(')),
    ("os.path.isfile() check (TOCTOU risk)", re.compile(r'\bos\.path\.isfile\s*\(')),
    ("tempfile without delete=False", re.compile(
        r'\btempfile\.(?:NamedTemporaryFile|mkstemp)\s*\([^)]*\)'
    )),
]

# TOCTOU detection: look for exists() + open() within close proximity in same file
TOCTOU_EXISTS_PAT = re.compile(r'\bos\.path\.(?:exists|isfile)\s*\(')
TOCTOU_OPEN_PAT = re.compile(r'\bopen\s*\(')
JS_EXISTS_PAT = re.compile(r'\bfs\.existsSync\s*\(')
JS_WRITE_PAT = re.compile(r'\bfs\.(?:writeFileSync|appendFileSync|writeFile|open)\s*\(')

EXTENSIONS = ("*.py", "*.js", "*.ts")


def _find_toctou(content: str, exists_pat: re.Pattern, action_pat: re.Pattern, window: int = 10) -> list[int]:
    """Return line numbers where exists check is followed by file action within `window` lines."""
    lines = content.splitlines()
    findings = []
    for i, line in enumerate(lines):
        if exists_pat.search(line):
            # Check following window lines for the action pattern
            for j in range(i + 1, min(i + window + 1, len(lines))):
                if action_pat.search(lines[j]):
                    findings.append(i + 1)  # 1-indexed
                    break
    return findings


class WbRaceConditionPlugin(PluginBase):
    name = "wb_race_condition"
    description = "Detect TOCTOU race condition patterns (os.path.exists + open, fs.existsSync + writeFileSync)"
    category = "whitebox"
    phase = 2
    base_severity = Severity.MEDIUM

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.path:
            return []

        root = Path(target.path)
        if not root.exists():
            return []

        results: list[Result] = []

        for ext in EXTENSIONS:
            for src_file in root.rglob(ext):
                if not src_file.is_file() or should_skip(src_file):
                    continue
                try:
                    if src_file.stat().st_size > MAX_FILE_SIZE:
                        continue
                    content = src_file.read_text(errors="ignore")
                except OSError:
                    continue

                is_py = src_file.suffix == ".py"
                is_js = src_file.suffix in (".js", ".ts")

                if is_py:
                    toctou_lines = _find_toctou(content, TOCTOU_EXISTS_PAT, TOCTOU_OPEN_PAT)
                    for lineno in toctou_lines:
                        line_text = content.splitlines()[lineno - 1]
                        results.append(
                            Result(
                                plugin_name=self.name,
                                base_severity=Severity.MEDIUM,
                                title="TOCTOU Race Condition: os.path.exists() + open()",
                                description=(
                                    f"TOCTOU race condition detected in "
                                    f"'{src_file.relative_to(root)}' at line {lineno}. "
                                    "Checking file existence then opening it is a race condition."
                                ),
                                evidence=f"{src_file.relative_to(root)}:{lineno}: {line_text.strip()[:120]}",
                                recommendation=(
                                    "Open the file directly and handle FileNotFoundError/IOError instead "
                                    "of checking existence first. This eliminates the TOCTOU window."
                                ),
                                cwe_id="CWE-362",
                                rule_id="wb_race_condition",
                                endpoint=str(src_file),
                            )
                        )

                if is_js:
                    toctou_lines = _find_toctou(content, JS_EXISTS_PAT, JS_WRITE_PAT)
                    for lineno in toctou_lines:
                        line_text = content.splitlines()[lineno - 1]
                        results.append(
                            Result(
                                plugin_name=self.name,
                                base_severity=Severity.MEDIUM,
                                title="TOCTOU Race Condition: fs.existsSync() + fs.writeFileSync()",
                                description=(
                                    f"TOCTOU race condition detected in "
                                    f"'{src_file.relative_to(root)}' at line {lineno}. "
                                    "Checking file existence then writing is a race condition."
                                ),
                                evidence=f"{src_file.relative_to(root)}:{lineno}: {line_text.strip()[:120]}",
                                recommendation=(
                                    "Use try/catch around fs.writeFileSync directly instead of "
                                    "checking existence first. This eliminates the TOCTOU window."
                                ),
                                cwe_id="CWE-362",
                                rule_id="wb_race_condition",
                                endpoint=str(src_file),
                            )
                        )

        return results
