"""Tests for cross-file taint tracking."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from vibee_hacker.core.taint_tracker import (
    TaintFlow,
    TaintSink,
    TaintSource,
    TaintTracker,
)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _write(tmp_path: Path, name: str, code: str) -> str:
    p = tmp_path / name
    p.write_text(textwrap.dedent(code))
    return str(p)


# ---------------------------------------------------------------------------
# Python taint tests
# ---------------------------------------------------------------------------

def test_python_sqli_flow(tmp_path):
    """request.args assignment → cursor.execute call is detected."""
    src = _write(tmp_path, "app.py", """\
        user_id = request.args.get("id")
        cursor.execute(user_id)
    """)
    tracker = TaintTracker(language="python")
    flows = tracker.analyze_file(src)
    assert len(flows) >= 1
    flow = flows[0]
    assert flow.sink.sink_type == "sql"
    assert flow.source.source_type == "request"
    assert flow.source.variable == "user_id"


def test_python_cmdi_flow(tmp_path):
    """request.form assignment → os.system call is detected."""
    src = _write(tmp_path, "app.py", """\
        cmd = request.form.get("cmd")
        os.system(cmd)
    """)
    tracker = TaintTracker(language="python")
    flows = tracker.analyze_file(src)
    assert len(flows) >= 1
    assert flows[0].sink.sink_type == "exec"
    assert flows[0].source.source_type == "request"


def test_python_xss_flow(tmp_path):
    """request.args assignment → render_template_string call is detected."""
    src = _write(tmp_path, "app.py", """\
        tmpl = request.args.get("t")
        render_template_string(tmpl)
    """)
    tracker = TaintTracker(language="python")
    flows = tracker.analyze_file(src)
    assert len(flows) >= 1
    assert flows[0].sink.sink_type == "html"


def test_python_no_flow(tmp_path):
    """Safe code with no source→sink path returns no flows."""
    src = _write(tmp_path, "safe.py", """\
        name = "Alice"
        cursor.execute("SELECT 1")
    """)
    tracker = TaintTracker(language="python")
    flows = tracker.analyze_file(src)
    assert flows == []


def test_python_syntax_error(tmp_path):
    """Files with syntax errors return empty flows gracefully."""
    src = _write(tmp_path, "bad.py", "def broken(:\n    pass\n")
    tracker = TaintTracker(language="python")
    flows = tracker.analyze_file(src)
    assert flows == []


# ---------------------------------------------------------------------------
# JavaScript taint tests
# ---------------------------------------------------------------------------

def test_javascript_sqli_flow(tmp_path):
    """req.query assignment → .query( call is detected."""
    src = _write(tmp_path, "server.js", """\
        const userInput = req.query.id;
        db.query(userInput);
    """)
    tracker = TaintTracker(language="javascript")
    flows = tracker.analyze_file(src)
    assert len(flows) >= 1
    assert flows[0].sink.sink_type == "sql"
    assert flows[0].source.source_type == "request"


def test_javascript_xss_flow(tmp_path):
    """req.body assignment → .innerHTML sink is detected."""
    src = _write(tmp_path, "server.js", """\
        const data = req.body.content;
        element.innerHTML = data;
    """)
    tracker = TaintTracker(language="javascript")
    flows = tracker.analyze_file(src)
    assert len(flows) >= 1
    assert flows[0].sink.sink_type == "html"


def test_javascript_no_flow(tmp_path):
    """Clean JS code with no source→sink path returns no flows."""
    src = _write(tmp_path, "clean.js", """\
        const x = 42;
        console.log(x);
    """)
    tracker = TaintTracker(language="javascript")
    flows = tracker.analyze_file(src)
    assert flows == []


# ---------------------------------------------------------------------------
# Directory analysis
# ---------------------------------------------------------------------------

def test_analyze_directory(tmp_path):
    """analyze_directory scans all .py files and aggregates flows."""
    _write(tmp_path, "a.py", """\
        user = request.args.get("u")
        cursor.execute(user)
    """)
    _write(tmp_path, "b.py", """\
        cmd = request.form.get("c")
        os.system(cmd)
    """)
    # Non-Python file should be ignored
    (tmp_path / "ignore.txt").write_text("not python")

    tracker = TaintTracker(language="python")
    flows = tracker.analyze_directory(str(tmp_path))
    assert len(flows) >= 2


# ---------------------------------------------------------------------------
# Dataclass / field tests
# ---------------------------------------------------------------------------

def test_taint_source_fields():
    """TaintSource stores all expected fields."""
    src = TaintSource(
        file="/app/views.py", line=10, function="get_user",
        variable="uid", source_type="request",
    )
    assert src.file == "/app/views.py"
    assert src.line == 10
    assert src.function == "get_user"
    assert src.variable == "uid"
    assert src.source_type == "request"


def test_taint_flow_confidence(tmp_path):
    """Request-sourced flows should have 'high' confidence."""
    src = _write(tmp_path, "app.py", """\
        val = request.args.get("x")
        cursor.execute(val)
    """)
    tracker = TaintTracker(language="python")
    flows = tracker.analyze_file(src)
    assert flows[0].confidence == "high"


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def test_get_summary(tmp_path):
    """get_summary returns correct counts after analysis."""
    _write(tmp_path, "app.py", """\
        q = request.args.get("q")
        cursor.execute(q)
    """)
    tracker = TaintTracker(language="python")
    tracker.analyze_directory(str(tmp_path))
    summary = tracker.get_summary()
    assert summary["flows"] >= 1
    assert summary["sources"] >= 1
    assert summary["sinks"] >= 1
    assert "sql" in summary["by_sink_type"]
