"""Cross-file taint tracking: trace data flow from sources to sinks."""

from __future__ import annotations
import ast
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class TaintSource:
    """A taint source (user input entry point)."""
    file: str
    line: int
    function: str
    variable: str
    source_type: str  # "param", "request", "env", "file", "db"


@dataclass
class TaintSink:
    """A taint sink (dangerous operation)."""
    file: str
    line: int
    function: str
    call: str
    sink_type: str  # "sql", "exec", "html", "file", "network"


@dataclass
class TaintFlow:
    """A complete taint flow from source to sink."""
    source: TaintSource
    sink: TaintSink
    path: list[str] = field(default_factory=list)  # intermediate variable names
    confidence: str = "medium"  # low, medium, high


# Known source patterns
SOURCES = {
    "python": {
        "request.args": "request",
        "request.form": "request",
        "request.json": "request",
        "request.data": "request",
        "request.cookies": "request",
        "request.headers": "request",
        "input(": "param",
        "sys.argv": "param",
        "os.environ": "env",
        "open(": "file",
    },
    "javascript": {
        "req.body": "request",
        "req.query": "request",
        "req.params": "request",
        "req.headers": "request",
        "req.cookies": "request",
        "process.env": "env",
        "document.location": "request",
        "window.location": "request",
    },
}

# Known sink patterns
SINKS = {
    "python": {
        "cursor.execute": "sql",
        "db.execute": "sql",
        "os.system": "exec",
        "subprocess.call": "exec",
        "subprocess.run": "exec",
        "subprocess.Popen": "exec",
        "eval(": "exec",
        "exec(": "exec",
        "render_template_string": "html",
        "Markup(": "html",
        "open(": "file",
        "requests.get": "network",
        "httpx.get": "network",
    },
    "javascript": {
        ".query(": "sql",
        ".exec(": "exec",
        "eval(": "exec",
        ".innerHTML": "html",
        "document.write": "html",
        "res.send(": "html",
        "child_process": "exec",
        "fs.writeFile": "file",
    },
}


class TaintTracker:
    """Track taint flow across files."""

    def __init__(self, language: str = "python"):
        self.language = language
        self.sources: list[TaintSource] = []
        self.sinks: list[TaintSink] = []
        self.flows: list[TaintFlow] = []
        self._var_origins: dict[str, TaintSource] = {}  # var_name -> source

    def analyze_file(self, filepath: str) -> list[TaintFlow]:
        """Analyze a single file for taint flows."""
        try:
            with open(filepath) as f:
                content = f.read()
        except (OSError, UnicodeDecodeError):
            return []

        if self.language == "python":
            return self._analyze_python(filepath, content)
        elif self.language == "javascript":
            return self._analyze_javascript(filepath, content)
        return []

    def analyze_directory(self, dirpath: str, extensions: list[str] | None = None) -> list[TaintFlow]:
        """Analyze all files in a directory."""
        if extensions is None:
            extensions = [".py"] if self.language == "python" else [".js", ".ts"]

        all_flows = []
        for path in Path(dirpath).rglob("*"):
            if path.suffix in extensions and path.is_file():
                flows = self.analyze_file(str(path))
                all_flows.extend(flows)
        return all_flows

    def _analyze_python(self, filepath: str, content: str) -> list[TaintFlow]:
        """Python-specific taint analysis using AST."""
        flows = []
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return []

        lines = content.split("\n")
        sources_map = SOURCES.get("python", {})
        sinks_map = SINKS.get("python", {})

        # Find tainted variables (assigned from sources)
        tainted_vars: dict[str, TaintSource] = {}

        for node in ast.walk(tree):
            # Find assignments from sources
            if isinstance(node, ast.Assign):
                line_content = lines[node.lineno - 1] if node.lineno <= len(lines) else ""

                for pattern, src_type in sources_map.items():
                    if pattern in line_content:
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                source = TaintSource(
                                    file=filepath, line=node.lineno,
                                    function="", variable=target.id,
                                    source_type=src_type,
                                )
                                tainted_vars[target.id] = source
                                self.sources.append(source)

            # Find sinks that use tainted variables
            if isinstance(node, ast.Call):
                line_content = lines[node.lineno - 1] if node.lineno <= len(lines) else ""

                for pattern, sink_type in sinks_map.items():
                    if pattern in line_content:
                        # Check if any argument is tainted
                        for arg in node.args:
                            if isinstance(arg, ast.Name) and arg.id in tainted_vars:
                                source = tainted_vars[arg.id]
                                sink = TaintSink(
                                    file=filepath, line=node.lineno,
                                    function="", call=pattern,
                                    sink_type=sink_type,
                                )
                                self.sinks.append(sink)
                                flow = TaintFlow(
                                    source=source, sink=sink,
                                    path=[source.variable],
                                    confidence="high" if source.source_type == "request" else "medium",
                                )
                                flows.append(flow)
                                self.flows.append(flow)

        return flows

    def _analyze_javascript(self, filepath: str, content: str) -> list[TaintFlow]:
        """JavaScript taint analysis using regex (no AST parser needed)."""
        flows = []
        lines = content.split("\n")
        sources_map = SOURCES.get("javascript", {})
        sinks_map = SINKS.get("javascript", {})

        tainted_vars: dict[str, TaintSource] = {}

        for i, line in enumerate(lines, 1):
            # Find assignments from sources
            for pattern, src_type in sources_map.items():
                if pattern in line:
                    # Try to extract variable name
                    match = re.match(r'\s*(?:const|let|var)\s+(\w+)\s*=', line)
                    if match:
                        var_name = match.group(1)
                        source = TaintSource(
                            file=filepath, line=i, function="",
                            variable=var_name, source_type=src_type,
                        )
                        tainted_vars[var_name] = source
                        self.sources.append(source)

            # Find sinks using tainted vars
            for pattern, sink_type in sinks_map.items():
                if pattern in line:
                    for var_name, source in tainted_vars.items():
                        if var_name in line:
                            sink = TaintSink(
                                file=filepath, line=i, function="",
                                call=pattern, sink_type=sink_type,
                            )
                            self.sinks.append(sink)
                            flow = TaintFlow(
                                source=source, sink=sink,
                                path=[var_name], confidence="medium",
                            )
                            flows.append(flow)
                            self.flows.append(flow)

        return flows

    def get_summary(self) -> dict:
        by_sink_type: dict[str, int] = {}
        for flow in self.flows:
            key = flow.sink.sink_type
            by_sink_type[key] = by_sink_type.get(key, 0) + 1
        return {
            "sources": len(self.sources),
            "sinks": len(self.sinks),
            "flows": len(self.flows),
            "by_sink_type": by_sink_type,
        }
