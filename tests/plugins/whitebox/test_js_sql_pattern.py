# tests/plugins/whitebox/test_js_sql_pattern.py
"""Tests for JsSqlPatternPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.js_sql_pattern import JsSqlPatternPlugin
from vibee_hacker.core.models import Target, Severity


class TestJsSqlPattern:
    @pytest.fixture
    def plugin(self):
        return JsSqlPatternPlugin()

    @pytest.mark.asyncio
    async def test_template_literal_sql_detected(self, plugin, tmp_path):
        """Template literal SQL injection is flagged as CRITICAL."""
        (tmp_path / "db.js").write_text(
            "async function getUser(name) {\n"
            "  const query = `SELECT * FROM users WHERE name = '${name}'`;\n"
            "  return await db.query(query);\n"
            "}\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.base_severity == Severity.CRITICAL
        assert r.rule_id == "js_sql_injection"
        assert r.cwe_id == "CWE-89"

    @pytest.mark.asyncio
    async def test_parameterized_query_clean(self, plugin, tmp_path):
        """Parameterized queries in JS return empty."""
        (tmp_path / "db.js").write_text(
            "async function getUser(name) {\n"
            "  const query = 'SELECT * FROM users WHERE name = ?';\n"
            "  return await db.query(query, [name]);\n"
            "}\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_path_returns_empty(self, plugin):
        target = Target(url="https://example.com")
        results = await plugin.run(target)
        assert results == []
