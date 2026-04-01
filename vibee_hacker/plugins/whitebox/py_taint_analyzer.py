"""Python Taint Analyzer — traces data flow from sources to sinks."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase
from vibee_hacker.core.file_utils import should_skip, MAX_FILE_SIZE

# Sources: functions/attributes that return user-controlled data
SOURCES = {
    # Flask
    "request.args", "request.form", "request.json", "request.data",
    "request.files", "request.cookies", "request.headers",
    # Django
    "request.GET", "request.POST", "request.body", "request.META",
    # Common
    "input", "sys.argv", "os.environ",
}

# Sinks: functions where tainted data is dangerous
SINKS: dict[str, tuple[str, Severity, str]] = {
    "eval": ("CWE-94", Severity.CRITICAL, "Code execution via eval()"),
    "exec": ("CWE-94", Severity.CRITICAL, "Code execution via exec()"),
    "os.system": ("CWE-78", Severity.CRITICAL, "OS command injection"),
    "subprocess.call": ("CWE-78", Severity.CRITICAL, "OS command injection"),
    "subprocess.run": ("CWE-78", Severity.CRITICAL, "OS command injection"),
    "subprocess.Popen": ("CWE-78", Severity.CRITICAL, "OS command injection"),
    "cursor.execute": ("CWE-89", Severity.CRITICAL, "SQL injection"),
    "execute": ("CWE-89", Severity.CRITICAL, "SQL injection via execute()"),
    "pickle.loads": ("CWE-502", Severity.CRITICAL, "Unsafe deserialization"),
    "yaml.load": ("CWE-502", Severity.HIGH, "Unsafe YAML loading"),
    "render_template_string": ("CWE-79", Severity.HIGH, "XSS via template"),
    "Markup": ("CWE-79", Severity.HIGH, "XSS via Markup()"),
    "redirect": ("CWE-601", Severity.MEDIUM, "Open redirect"),
    "HttpResponseRedirect": ("CWE-601", Severity.MEDIUM, "Open redirect"),
}

# Sanitizers: functions that clean tainted data
# NOTE: "str" and "bool" are intentionally excluded — they do NOT prevent SQL injection.
# Only "int" and "float" are safe as they convert to numeric types with no injection risk.
SANITIZERS = {
    "html.escape", "bleach.clean", "markupsafe.escape", "escape",
    "shlex.quote", "int", "float",
    "quote", "urlencode",
}


@dataclass
class TaintState:
    """Track tainted variables in a function scope."""
    tainted: dict[str, list[str]] = field(default_factory=dict)  # var_name -> [source_chain]

    def mark_tainted(self, var: str, chain: list[str]) -> None:
        self.tainted[var] = chain

    def is_tainted(self, var: str) -> bool:
        return var in self.tainted

    def get_chain(self, var: str) -> list[str]:
        return self.tainted.get(var, [])

    def sanitize(self, var: str) -> None:
        self.tainted.pop(var, None)


class PyTaintAnalyzerPlugin(PluginBase):
    name = "py_taint_analyzer"
    description = "Python taint analysis: traces user input to dangerous sinks"
    category = "whitebox"
    phase = 3
    base_severity = Severity.CRITICAL
    detection_criteria = "User input flows to dangerous function without sanitization"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.path:
            return []

        results: list[Result] = []
        root = Path(target.path)
        for src_file in root.rglob("*.py"):
            if should_skip(src_file) or src_file.stat().st_size > MAX_FILE_SIZE:
                continue
            try:
                source = src_file.read_text(errors="ignore")
                tree = ast.parse(source, filename=str(src_file))
            except (SyntaxError, OSError):
                continue

            file_results = self._analyze_file(tree, str(src_file), source)
            results.extend(file_results)

        return results

    def _analyze_file(self, tree: ast.AST, filepath: str, source: str) -> list[Result]:
        results: list[Result] = []
        lines = source.splitlines()

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_results = self._analyze_function(node, filepath, lines)
                results.extend(func_results)

        return results

    def _iter_stmts(self, body: list) -> "Generator[ast.AST, None, None]":
        """Iterate AST statements in execution order."""
        for stmt in body:
            yield stmt
            # Recurse into compound statements
            for child_body in ('body', 'orelse', 'finalbody', 'handlers'):
                if hasattr(stmt, child_body):
                    child = getattr(stmt, child_body)
                    if isinstance(child, list):
                        yield from self._iter_stmts(child)

    def _analyze_function(
        self,
        func: ast.FunctionDef | ast.AsyncFunctionDef,
        filepath: str,
        lines: list[str],
    ) -> list[Result]:
        results: list[Result] = []
        state = TaintState()

        # Walk statements in execution order (not unordered ast.walk)
        for node in self._iter_stmts(func.body):
            # Step 1: Assignments — detect sources and propagate taint
            if isinstance(node, ast.Assign):
                self._process_assign(node, filepath, state)

            # Step 2: Detect sanitizers removing taint
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                func_name = self._node_to_str(node.value.func)
                if func_name in SANITIZERS:
                    for target_node in node.targets:
                        var_name = self._node_to_str(target_node)
                        if var_name:
                            state.sanitize(var_name)

            # Step 3: Detect sinks with tainted arguments.
            # _iter_stmts yields statement nodes. Calls can appear as:
            #   ast.Expr(value=ast.Call(...))   — standalone call statement
            #   ast.Assign(value=ast.Call(...)) — assigned call, e.g. result = eval(x)
            #   ast.Call (rare: already a node) — direct node (defensive)
            call_node: ast.AST | None = None
            if isinstance(node, ast.Call):
                call_node = node
            elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                call_node = node.value
            elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                call_node = node.value

            if call_node is not None and isinstance(call_node, ast.Call):
                func_name = self._node_to_str(call_node.func)
                sink_info = SINKS.get(func_name)
                if sink_info:
                    cwe, severity, desc = sink_info
                    tainted_arg = self._find_tainted_arg(call_node, state)
                    if tainted_arg is not None:
                        arg_name, chain = tainted_arg
                        full_chain = chain + [
                            f"{filepath}:{call_node.lineno}: {func_name}({arg_name})"
                        ]
                        results.append(Result(
                            plugin_name=self.name,
                            base_severity=severity,
                            title=f"Taint: {desc} in {func_name}()",
                            description=(
                                f"User input flows to {func_name}() without sanitization"
                            ),
                            evidence="\n".join(full_chain),
                            endpoint=f"{filepath}:{node.lineno}",
                            cwe_id=cwe,
                            rule_id=f"taint_{func_name.replace('.', '_')}",
                            recommendation=(
                                f"Sanitize user input before passing to {func_name}()"
                            ),
                        ))
                        return results  # One finding per function

        return results

    def _process_assign(self, node: ast.Assign, filepath: str, state: TaintState) -> None:
        """Update taint state from an assignment node."""
        value_str = self._node_to_str(node.value)

        # Direct source assignment: x = request.args.get(...)
        if self._is_source(value_str):
            for target_node in node.targets:
                var_name = self._node_to_str(target_node)
                if var_name:
                    state.mark_tainted(
                        var_name,
                        [f"{filepath}:{node.lineno}: {var_name} = {value_str}"],
                    )
            return

        # Propagate taint through simple variable copy: b = a
        if isinstance(node.value, ast.Name) and state.is_tainted(node.value.id):
            for target_node in node.targets:
                var_name = self._node_to_str(target_node)
                if var_name:
                    chain = state.get_chain(node.value.id) + [
                        f"{filepath}:{node.lineno}: {var_name} = {node.value.id}"
                    ]
                    state.mark_tainted(var_name, chain)

    def _is_source(self, value_str: str) -> bool:
        if not value_str:
            return False
        return any(src in value_str for src in SOURCES)

    def _node_to_str(self, node: ast.AST) -> str:
        """Convert an AST node to a dotted string representation."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = self._node_to_str(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        if isinstance(node, ast.Subscript):
            return self._node_to_str(node.value)
        if isinstance(node, ast.Call):
            return self._node_to_str(node.func)
        return ""

    def _get_arg_name(self, node: ast.AST) -> str:
        """Extract a variable name from an argument node (handles f-strings, concat)."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return self._node_to_str(node)
        if isinstance(node, ast.JoinedStr):
            # f-string: return first formatted value name
            for val in node.values:
                if isinstance(val, ast.FormattedValue):
                    name = self._get_arg_name(val.value)
                    if name:
                        return name
        if isinstance(node, ast.BinOp):
            # String concat: check both sides
            left = self._get_arg_name(node.left)
            if left:
                return left
            return self._get_arg_name(node.right)
        return ""

    def _find_tainted_arg(
        self, node: ast.Call, state: TaintState
    ) -> tuple[str, list[str]] | None:
        """Return (arg_name, chain) if any positional or keyword argument is tainted."""
        for arg in node.args:
            arg_name = self._get_arg_name(arg)
            if arg_name and state.is_tainted(arg_name):
                return arg_name, state.get_chain(arg_name)
        for kw in node.keywords:
            arg_name = self._get_arg_name(kw.value)
            if arg_name and state.is_tainted(arg_name):
                return arg_name, state.get_chain(arg_name)
        return None
