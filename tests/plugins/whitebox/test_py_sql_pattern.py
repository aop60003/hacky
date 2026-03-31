# tests/plugins/whitebox/test_py_sql_pattern.py
"""Tests for PySqlPatternPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.py_sql_pattern import PySqlPatternPlugin
from vibee_hacker.core.models import Target, Severity


class TestPySqlPattern:
    @pytest.fixture
    def plugin(self):
        return PySqlPatternPlugin()

    @pytest.mark.asyncio
    async def test_fstring_sql_detected(self, plugin, tmp_path):
        """f-string SQL injection is flagged as CRITICAL."""
        (tmp_path / "db.py").write_text(
            'def get_user(name):\n'
            '    query = f"SELECT * FROM users WHERE name = \'{name}\'"\n'
            '    cursor.execute(query)\n'
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.base_severity == Severity.CRITICAL
        assert r.rule_id == "py_sql_injection"
        assert r.cwe_id == "CWE-89"

    @pytest.mark.asyncio
    async def test_parameterized_query_clean(self, plugin, tmp_path):
        """Parameterized queries are not flagged."""
        (tmp_path / "db.py").write_text(
            'def get_user(name):\n'
            '    cursor.execute("SELECT * FROM users WHERE name = %s", (name,))\n'
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_path_returns_empty(self, plugin):
        target = Target(url="https://example.com")
        results = await plugin.run(target)
        assert results == []
