# tests/plugins/whitebox/test_todo_fixme_security.py
"""Tests for TodoFixmeSecurityPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.todo_fixme_security import TodoFixmeSecurityPlugin
from vibee_hacker.core.models import Target, Severity


class TestTodoFixmeSecurity:
    @pytest.fixture
    def plugin(self):
        return TodoFixmeSecurityPlugin()

    # ------------------------------------------------------------------ #
    # Test 1: TODO: fix security found
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_security_todo_detected(self, plugin, tmp_path):
        """A comment with TODO + security keyword is flagged as INFO."""
        (tmp_path / "auth.py").write_text(
            "def login(user, pw):\n"
            "    # TODO: fix security issue with password hashing\n"
            "    pass\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.base_severity == Severity.INFO
        assert r.rule_id == "security_todo"

    # ------------------------------------------------------------------ #
    # Test 2: Normal TODOs only — not flagged
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_normal_todos_not_flagged(self, plugin, tmp_path):
        """Generic TODO/FIXME without security keywords are not flagged."""
        (tmp_path / "app.py").write_text(
            "# TODO: add unit tests\n"
            "# FIXME: fix the UI layout\n"
            "# TODO: improve performance\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []

    # ------------------------------------------------------------------ #
    # Test 3: No path
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_no_path_returns_empty(self, plugin):
        target = Target(url="https://example.com")
        results = await plugin.run(target)
        assert results == []

    # ------------------------------------------------------------------ #
    # Bonus: FIXME.*vuln and HACK.*auth detected
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_fixme_vuln_detected(self, plugin, tmp_path):
        (tmp_path / "api.py").write_text(
            "# FIXME: this is vulnerable to injection\n"
            "# HACK: auth bypass for testing\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 2
        rule_ids = {r.rule_id for r in results}
        assert "security_todo" in rule_ids
