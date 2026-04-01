# tests/plugins/whitebox/test_dep_collector.py
"""Tests for DepCollectorPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.dep_collector import DepCollectorPlugin
from vibee_hacker.core.models import Target, Severity


class TestDepCollector:
    @pytest.fixture
    def plugin(self):
        return DepCollectorPlugin()

    # ------------------------------------------------------------------ #
    # Test 1: requirements.txt found
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_requirements_txt_found(self, plugin, tmp_path):
        """requirements.txt is parsed and packages reported."""
        (tmp_path / "requirements.txt").write_text(
            "flask==2.3.0\nrequests>=2.28.0\nsqlalchemy\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) == 1
        r = results[0]
        assert r.base_severity == Severity.INFO
        assert r.rule_id == "dependencies_collected"
        assert "requirements.txt" in r.evidence
        assert "flask" in r.evidence.lower()

    # ------------------------------------------------------------------ #
    # Test 2: No dep files
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_no_dep_files_returns_empty(self, plugin, tmp_path):
        """A directory without dependency files returns no results."""
        (tmp_path / "main.py").write_text("print('hello')\n")
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
    # Bonus: package.json parsed
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_package_json_parsed(self, plugin, tmp_path):
        import json
        pkg = {"name": "myapp", "dependencies": {"express": "^4.18.0", "lodash": "4.17.21"}}
        (tmp_path / "package.json").write_text(json.dumps(pkg))
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) == 1
        assert "express" in results[0].evidence.lower()
