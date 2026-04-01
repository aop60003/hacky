# tests/plugins/whitebox/test_project_mapper.py
"""Tests for ProjectMapperPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.project_mapper import ProjectMapperPlugin
from vibee_hacker.core.models import Target, Severity


class TestProjectMapper:
    @pytest.fixture
    def plugin(self):
        return ProjectMapperPlugin()

    # ------------------------------------------------------------------ #
    # Test 1: Project with main.py
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_entry_point_found(self, plugin, tmp_path):
        """A directory with main.py is detected as entry point."""
        (tmp_path / "main.py").write_text("if __name__ == '__main__':\n    pass\n")
        (tmp_path / "helper.py").write_text("def foo(): pass\n")
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) == 1
        r = results[0]
        assert r.base_severity == Severity.INFO
        assert r.rule_id == "project_map"
        assert "main.py" in r.evidence

    # ------------------------------------------------------------------ #
    # Test 2: Empty dir still returns a result (0 files)
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_empty_dir_returns_result(self, plugin, tmp_path):
        """Empty directory returns a result with 0 files."""
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) == 1
        assert "0" in results[0].evidence

    # ------------------------------------------------------------------ #
    # Test 3: No path
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_no_path_returns_empty(self, plugin):
        target = Target(url="https://example.com")
        results = await plugin.run(target)
        assert results == []

    # ------------------------------------------------------------------ #
    # Bonus: Config file detected
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_config_file_found(self, plugin, tmp_path):
        (tmp_path / "settings.py").write_text("DEBUG = True\n")
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) == 1
        assert "settings.py" in results[0].evidence
