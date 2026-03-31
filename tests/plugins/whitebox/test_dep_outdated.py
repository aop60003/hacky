# tests/plugins/whitebox/test_dep_outdated.py
"""Tests for DepOutdatedPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.dep_outdated import DepOutdatedPlugin
from vibee_hacker.core.models import Target


class TestDepOutdated:
    @pytest.fixture
    def plugin(self):
        return DepOutdatedPlugin()

    @pytest.mark.asyncio
    async def test_very_old_package_flagged(self, plugin, tmp_path):
        """A package pinned to a very old major version is flagged."""
        (tmp_path / "requirements.txt").write_text(
            "django==1.8.0\n"
            "flask==0.12.0\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        assert all(r.rule_id == "dep_outdated_package" for r in results)

    @pytest.mark.asyncio
    async def test_current_versions_no_findings(self, plugin, tmp_path):
        """Modern package versions produce no results."""
        (tmp_path / "requirements.txt").write_text(
            "django==4.2.0\n"
            "flask==3.0.0\n"
            "requests==2.31.0\n"
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
    async def test_no_path_returns_empty(self, plugin):
        """Target with no path returns empty."""
        target = Target(url="https://example.com")
        results = await plugin.run(target)
        assert results == []
