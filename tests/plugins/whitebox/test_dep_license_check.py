# tests/plugins/whitebox/test_dep_license_check.py
"""Tests for DepLicenseCheckPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.dep_license_check import DepLicenseCheckPlugin
from vibee_hacker.core.models import Target


class TestDepLicenseCheck:
    @pytest.fixture
    def plugin(self):
        return DepLicenseCheckPlugin()

    @pytest.mark.asyncio
    async def test_gpl_license_flagged(self, plugin, tmp_path):
        """GPL license in package.json is flagged."""
        (tmp_path / "package.json").write_text(
            '{\n'
            '  "name": "my-app",\n'
            '  "license": "GPL-3.0",\n'
            '  "dependencies": {}\n'
            '}\n'
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        assert all(r.rule_id == "dep_license_concern" for r in results)

    @pytest.mark.asyncio
    async def test_agpl_license_flagged(self, plugin, tmp_path):
        """AGPL license in package.json is flagged."""
        (tmp_path / "package.json").write_text(
            '{"name": "my-app", "license": "AGPL-3.0"}\n'
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1

    @pytest.mark.asyncio
    async def test_mit_license_no_findings(self, plugin, tmp_path):
        """MIT license produces no results."""
        (tmp_path / "package.json").write_text(
            '{"name": "my-app", "license": "MIT"}\n'
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_package_json_returns_empty(self, plugin, tmp_path):
        """No package.json yields empty results."""
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_path_returns_empty(self, plugin):
        """Target with no path returns empty."""
        target = Target(url="https://example.com")
        results = await plugin.run(target)
        assert results == []
