# tests/plugins/whitebox/test_dep_typosquat.py
"""Tests for DepTyposquatPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.dep_typosquat import DepTyposquatPlugin
from vibee_hacker.core.models import Target


class TestDepTyposquat:
    @pytest.fixture
    def plugin(self):
        return DepTyposquatPlugin()

    @pytest.mark.asyncio
    async def test_typosquat_package_flagged(self, plugin, tmp_path):
        """Known typosquat 'requets' in requirements.txt is flagged."""
        (tmp_path / "requirements.txt").write_text(
            "requets==2.28.0\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        assert all(r.rule_id == "dep_typosquat" for r in results)
        assert all(r.cwe_id == "CWE-506" for r in results)

    @pytest.mark.asyncio
    async def test_correct_package_name_no_findings(self, plugin, tmp_path):
        """Correct 'requests' package name produces no results."""
        (tmp_path / "requirements.txt").write_text(
            "requests==2.28.0\n"
            "django==4.2.0\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_dep_files_returns_empty(self, plugin, tmp_path):
        """No dependency files yields empty results."""
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_js_typosquat_flagged(self, plugin, tmp_path):
        """Known JS typosquat 'axois' in package.json is flagged."""
        (tmp_path / "package.json").write_text(
            '{\n'
            '  "dependencies": {\n'
            '    "axois": "0.21.0"\n'
            '  }\n'
            '}\n'
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        assert all(r.rule_id == "dep_typosquat" for r in results)

    @pytest.mark.asyncio
    async def test_no_path_returns_empty(self, plugin):
        """Target with no path returns empty."""
        target = Target(url="https://example.com")
        results = await plugin.run(target)
        assert results == []
