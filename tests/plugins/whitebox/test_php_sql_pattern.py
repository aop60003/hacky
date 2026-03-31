# tests/plugins/whitebox/test_php_sql_pattern.py
"""Tests for PhpSqlPatternPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.php_sql_pattern import PhpSqlPatternPlugin
from vibee_hacker.core.models import Target, Severity


class TestPhpSqlPattern:
    @pytest.fixture
    def plugin(self):
        return PhpSqlPatternPlugin()

    @pytest.mark.asyncio
    async def test_sql_concat_detected(self, plugin, tmp_path):
        """SQL string concatenation with variable is flagged."""
        (tmp_path / "db.php").write_text(
            "<?php\n"
            "$id = $_GET['id'];\n"
            "$query = \"SELECT * FROM users WHERE id = \" . $id;\n"
            "mysql_query($query);\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.base_severity == Severity.CRITICAL
        assert r.rule_id == "php_sql_injection"
        assert r.cwe_id == "CWE-89"

    @pytest.mark.asyncio
    async def test_prepared_statement_clean(self, plugin, tmp_path):
        """Prepared statements do not trigger a finding."""
        (tmp_path / "db.php").write_text(
            "<?php\n"
            "$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');\n"
            "$stmt->execute([$id]);\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_path_returns_empty(self, plugin):
        target = Target(url="https://example.com")
        results = await plugin.run(target)
        assert results == []
