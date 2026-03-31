# tests/plugins/whitebox/test_java_sql_pattern.py
"""Tests for JavaSqlPatternPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.java_sql_pattern import JavaSqlPatternPlugin
from vibee_hacker.core.models import Target, Severity


class TestJavaSqlPattern:
    @pytest.fixture
    def plugin(self):
        return JavaSqlPatternPlugin()

    @pytest.mark.asyncio
    async def test_statement_exec_concat_detected(self, plugin, tmp_path):
        """Statement.execute with string concat is flagged."""
        (tmp_path / "Dao.java").write_text(
            "import java.sql.*;\n"
            "public class Dao {\n"
            "    public void query(String id) throws Exception {\n"
            "        Statement stmt = conn.createStatement();\n"
            "        stmt.execute(\"SELECT * FROM users WHERE id = \" + id);\n"
            "    }\n"
            "}\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.base_severity == Severity.CRITICAL
        assert r.rule_id == "java_sql_injection"
        assert r.cwe_id == "CWE-89"

    @pytest.mark.asyncio
    async def test_prepared_statement_clean(self, plugin, tmp_path):
        """PreparedStatement is safe and returns empty."""
        (tmp_path / "Dao.java").write_text(
            "import java.sql.*;\n"
            "public class Dao {\n"
            "    public void query(String id) throws Exception {\n"
            "        PreparedStatement ps = conn.prepareStatement(\n"
            "            \"SELECT * FROM users WHERE id = ?\");\n"
            "        ps.setString(1, id);\n"
            "        ps.executeQuery();\n"
            "    }\n"
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
