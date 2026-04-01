"""JavaScript Taint Analyzer — regex-based source-to-sink flow detection."""

from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase
from vibee_hacker.core.file_utils import should_skip, MAX_FILE_SIZE

# User-controlled input sources (patterns matched in code)
SOURCES = [
    "req.query",
    "req.params",
    "req.body",
    "req.headers",
    "req.cookies",
    "location.search",
    "location.hash",
    "document.cookie",
    "process.argv",
    "useSearchParams",
]

# Sinks and their associated CWE + severity + description
SINKS: dict[str, tuple[str, Severity, str]] = {
    "eval(": ("CWE-94", Severity.CRITICAL, "Code execution via eval()"),
    "innerHTML": ("CWE-79", Severity.HIGH, "XSS via innerHTML"),
    "document.write(": ("CWE-79", Severity.HIGH, "XSS via document.write()"),
    "child_process.exec(": ("CWE-78", Severity.CRITICAL, "OS command injection"),
    "db.query(": ("CWE-89", Severity.CRITICAL, "SQL injection via db.query()"),
    "res.redirect(": ("CWE-601", Severity.MEDIUM, "Open redirect"),
    "fs.readFile(": ("CWE-22", Severity.HIGH, "Path traversal via fs.readFile()"),
    "Function(": ("CWE-94", Severity.CRITICAL, "Code execution via Function()"),
}

# Sanitizers that remove taint
SANITIZERS = [
    "DOMPurify.sanitize",
    "encodeURIComponent",
    "parseInt",
    "Number(",
    "escape(",
]

# Regex to extract variable name from an assignment like:
#   var foo = req.query.bar  OR  const foo = req.body.name
_ASSIGN_RE = re.compile(
    r"(?:var|let|const)\s+(\w+)\s*=\s*(.+)"
)
# Simpler: just grab identifier on left of =
_SIMPLE_ASSIGN_RE = re.compile(r"\b(\w+)\s*=\s*(.+)")

# Window for taint tracking: how many lines ahead to scan for sinks
WINDOW = 100


def _extract_assigned_var(line: str) -> tuple[str, str] | None:
    """Return (var_name, rhs) from an assignment line, or None."""
    m = _ASSIGN_RE.search(line)
    if m:
        return m.group(1), m.group(2)
    m = _SIMPLE_ASSIGN_RE.search(line)
    if m:
        return m.group(1), m.group(2)
    return None


def _line_contains_source(line: str) -> bool:
    return any(src in line for src in SOURCES)


def _line_contains_sanitizer(line: str) -> bool:
    return any(san in line for san in SANITIZERS)


def _find_sink_in_line(line: str) -> tuple[str, str, Severity, str] | None:
    """Return (sink_name, cwe, severity, description) if line contains a known sink."""
    for sink, (cwe, sev, desc) in SINKS.items():
        if sink in line:
            return sink, cwe, sev, desc
    return None


def _analyze_js_file(filepath: str, source: str) -> list[Result]:
    """Perform line-based taint analysis on a JS/TS file."""
    results: list[Result] = []
    lines = source.splitlines()
    n = len(lines)

    # We scan function-body-sized windows.
    # Simple approach: find lines with sources, track var names,
    # scan next WINDOW lines for sinks not preceded by sanitizers.

    i = 0
    while i < n:
        line = lines[i]

        if _line_contains_source(line):
            # If the source is immediately wrapped in a sanitizer on the same line, skip
            if _line_contains_sanitizer(line):
                i += 1
                continue

            # Try to extract the variable receiving the tainted value
            tainted_var: str | None = None
            assignment = _extract_assigned_var(line)
            if assignment:
                tainted_var = assignment[0]

            # Scan ahead for sinks
            end = min(i + WINDOW, n)
            sanitized = False

            for j in range(i + 1, end):
                check_line = lines[j]

                # If the variable is explicitly sanitized via reassignment, stop tracking it
                # Only clear taint when the tainted variable appears on the LEFT side of
                # an assignment (i.e., taintedVar = sanitize(taintedVar))
                if tainted_var and _line_contains_sanitizer(check_line):
                    if tainted_var in check_line:
                        assign = _extract_assigned_var(check_line)
                        if assign and assign[0] == tainted_var:
                            sanitized = True
                            break

                # Check if a sink uses our tainted variable (or raw source)
                sink_match = _find_sink_in_line(check_line)
                if sink_match:
                    sink_name, cwe, sev, desc = sink_match
                    # Only flag if our tainted variable (or raw source) appears in the sink line
                    var_in_line = (tainted_var and tainted_var in check_line) or _line_contains_source(check_line)
                    if var_in_line and not sanitized:
                        results.append(Result(
                            plugin_name="js_taint_analyzer",
                            base_severity=sev,
                            title=f"JS Taint: {desc}",
                            description=(
                                f"User-controlled input flows to '{sink_name}' "
                                f"without sanitization in {filepath}"
                            ),
                            evidence=(
                                f"Source ({lines[i].strip()}) → Sink ({check_line.strip()})"
                            ),
                            endpoint=f"{filepath}:{j + 1}",
                            cwe_id=cwe,
                            rule_id=f"js_taint_{sink_name.rstrip('(').replace('.', '_')}",
                            recommendation=(
                                f"Sanitize user input before passing to '{sink_name}'"
                            ),
                        ))
                        # One finding per source line
                        break

        i += 1

    return results


class JsTaintAnalyzerPlugin(PluginBase):
    name = "js_taint_analyzer"
    description = "JavaScript taint analysis: traces user input to dangerous sinks"
    category = "whitebox"
    phase = 3
    base_severity = Severity.CRITICAL
    detection_criteria = "User input flows to dangerous JS function without sanitization"

    def is_applicable(self, target: Target) -> bool:
        return bool(target.path)

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.path:
            return []

        results: list[Result] = []
        root = Path(target.path)

        for ext in ("*.js", "*.ts", "*.jsx", "*.tsx"):
            for src_file in root.rglob(ext):
                if should_skip(src_file):
                    continue
                try:
                    if src_file.stat().st_size > MAX_FILE_SIZE:
                        continue
                    source = src_file.read_text(errors="ignore")
                except OSError:
                    continue

                file_results = _analyze_js_file(str(src_file), source)
                results.extend(file_results)

        return results
