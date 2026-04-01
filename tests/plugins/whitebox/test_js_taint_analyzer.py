# tests/plugins/whitebox/test_js_taint_analyzer.py
"""Tests for JsTaintAnalyzerPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.js_taint_analyzer import JsTaintAnalyzerPlugin
from vibee_hacker.core.models import Target, Severity


class TestJsTaintAnalyzer:
    @pytest.fixture
    def plugin(self):
        return JsTaintAnalyzerPlugin()

    # ------------------------------------------------------------------ #
    # Test 1: req.query → eval() detected
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_req_query_to_eval(self, plugin, tmp_path):
        """req.query flowing into eval() is detected as code execution."""
        (tmp_path / "app.js").write_text(
            "function handler(req, res) {\n"
            "  var input = req.query.name;\n"
            "  eval(input);\n"
            "}\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.base_severity == Severity.CRITICAL
        assert r.cwe_id == "CWE-94"
        assert "js_taint" in r.rule_id

    # ------------------------------------------------------------------ #
    # Test 2: req.body → db.query() detected (SQL injection)
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_req_body_to_db_query(self, plugin, tmp_path):
        """req.body flowing into db.query() is detected as SQL injection."""
        (tmp_path / "routes.js").write_text(
            "function login(req, res) {\n"
            "  const user = req.body.username;\n"
            "  db.query('SELECT * FROM users WHERE name=' + user);\n"
            "}\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.cwe_id in ("CWE-89", "CWE-79", "CWE-94", "CWE-78")
        assert "js_taint" in r.rule_id

    # ------------------------------------------------------------------ #
    # Test 3: sanitized input (parseInt) no finding
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_sanitized_no_finding(self, plugin, tmp_path):
        """parseInt sanitizer prevents taint from being reported."""
        (tmp_path / "safe.js").write_text(
            "function getPage(req, res) {\n"
            "  var page = parseInt(req.query.page);\n"
            "  db.query('SELECT * FROM items LIMIT ' + page);\n"
            "}\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []

    # ------------------------------------------------------------------ #
    # Test 4: no source → no finding
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_no_source_no_finding(self, plugin, tmp_path):
        """Code with no user-input sources produces no results."""
        (tmp_path / "safe2.js").write_text(
            "function compute() {\n"
            "  var x = 'hardcoded';\n"
            "  eval(x);\n"
            "}\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []

    # ------------------------------------------------------------------ #
    # Test 5: no path → empty
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_no_path_returns_empty(self, plugin):
        target = Target(url="https://example.com")
        results = await plugin.run(target)
        assert results == []
