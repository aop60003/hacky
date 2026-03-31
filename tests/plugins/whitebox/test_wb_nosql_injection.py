# tests/plugins/whitebox/test_wb_nosql_injection.py
"""Tests for WbNoSqlInjectionPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.wb_nosql_injection import WbNoSqlInjectionPlugin
from vibee_hacker.core.models import Target, Severity


class TestWbNoSqlInjection:
    @pytest.fixture
    def plugin(self):
        return WbNoSqlInjectionPlugin()

    @pytest.mark.asyncio
    async def test_gt_operator_detected(self, plugin, tmp_path):
        """$gt operator in query is flagged as CRITICAL."""
        (tmp_path / "db.py").write_text(
            "def find_user(user_input):\n"
            "    return collection.find({\"$gt\": \"\"})\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.base_severity == Severity.CRITICAL
        assert r.rule_id == "wb_nosql_injection"
        assert r.cwe_id == "CWE-943"

    @pytest.mark.asyncio
    async def test_clean_query_returns_empty(self, plugin, tmp_path):
        """Clean parameterized queries return empty."""
        (tmp_path / "db.py").write_text(
            "def find_user(user_id):\n"
            "    return collection.find({'_id': user_id})\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_path_returns_empty(self, plugin):
        target = Target(url="https://example.com")
        results = await plugin.run(target)
        assert results == []
