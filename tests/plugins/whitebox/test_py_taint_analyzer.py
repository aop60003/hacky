# tests/plugins/whitebox/test_py_taint_analyzer.py
import pytest
from vibee_hacker.plugins.whitebox.py_taint_analyzer import PyTaintAnalyzerPlugin
from vibee_hacker.core.models import Target, Severity


class TestPyTaintAnalyzer:
    @pytest.fixture
    def plugin(self):
        return PyTaintAnalyzerPlugin()

    @pytest.mark.asyncio
    async def test_taint_source_to_sink(self, plugin, tmp_path):
        """User input flows directly to eval() — should detect."""
        code = '''
from flask import request

def handler():
    user_input = request.args.get("q")
    result = eval(user_input)
    return result
'''
        (tmp_path / "app.py").write_text(code)
        target = Target(path=str(tmp_path), mode="whitebox")
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.CRITICAL
        assert "eval" in results[0].title
        assert "CWE-94" in (results[0].cwe_id or "")

    @pytest.mark.asyncio
    async def test_taint_sql_injection(self, plugin, tmp_path):
        """User input in SQL query — should detect."""
        code = '''
from flask import request

def search():
    query = request.args.get("q")
    cursor.execute(query)
'''
        (tmp_path / "app.py").write_text(code)
        target = Target(path=str(tmp_path), mode="whitebox")
        results = await plugin.run(target)
        assert len(results) >= 1
        assert "CWE-89" in (results[0].cwe_id or "") or "execute" in results[0].title

    @pytest.mark.asyncio
    async def test_sanitized_input_no_finding(self, plugin, tmp_path):
        """Sanitized input should NOT trigger a finding."""
        code = '''
from flask import request

def handler():
    user_input = request.args.get("q")
    safe = int(user_input)
    eval(safe)
'''
        (tmp_path / "app.py").write_text(code)
        target = Target(path=str(tmp_path), mode="whitebox")
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_taint_chain_in_evidence(self, plugin, tmp_path):
        """Evidence should contain the full taint chain."""
        code = '''
from flask import request

def handler():
    data = request.form.get("name")
    result = eval(data)
'''
        (tmp_path / "app.py").write_text(code)
        target = Target(path=str(tmp_path), mode="whitebox")
        results = await plugin.run(target)
        assert len(results) >= 1
        assert "request.form" in results[0].evidence
        assert "eval" in results[0].evidence

    @pytest.mark.asyncio
    async def test_taint_propagation(self, plugin, tmp_path):
        """Taint should propagate through variable assignments."""
        code = '''
from flask import request

def handler():
    a = request.args.get("q")
    b = a
    eval(b)
'''
        (tmp_path / "app.py").write_text(code)
        target = Target(path=str(tmp_path), mode="whitebox")
        results = await plugin.run(target)
        assert len(results) >= 1

    @pytest.mark.asyncio
    async def test_no_source_no_finding(self, plugin, tmp_path):
        """Code without sources should produce no findings."""
        code = '''
def handler():
    data = "hello"
    eval(data)
'''
        (tmp_path / "app.py").write_text(code)
        target = Target(path=str(tmp_path), mode="whitebox")
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_no_path(self, plugin):
        target = Target(mode="whitebox")
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_syntax_error_skipped(self, plugin, tmp_path):
        """Files with syntax errors should be skipped, not crash."""
        (tmp_path / "bad.py").write_text("def foo(:\n  pass")
        target = Target(path=str(tmp_path), mode="whitebox")
        results = await plugin.run(target)
        assert results == []
