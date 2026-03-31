# tests/plugins/whitebox/test_dep_vuln_check.py
"""Tests for DepVulnCheckPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.dep_vuln_check import DepVulnCheckPlugin
from vibee_hacker.core.models import Target


class TestDepVulnCheck:
    @pytest.fixture
    def plugin(self):
        return DepVulnCheckPlugin()

    @pytest.mark.asyncio
    async def test_old_django_flagged(self, plugin, tmp_path):
        """Old django version in requirements.txt is flagged."""
        (tmp_path / "requirements.txt").write_text(
            "django==2.2.0\n"
            "requests==2.31.0\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        rule_ids = [r.rule_id for r in results]
        assert any(r == "dep_known_vulnerability" for r in rule_ids)
        # Check CWE-1104
        assert all(r.cwe_id == "CWE-1104" for r in results)

    @pytest.mark.asyncio
    async def test_all_up_to_date_no_findings(self, plugin, tmp_path):
        """All packages at safe versions produce no results."""
        (tmp_path / "requirements.txt").write_text(
            "django==4.2.0\n"
            "requests==2.31.0\n"
            "flask==2.3.3\n"
            "jinja2==3.1.3\n"
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
    async def test_old_js_package_flagged(self, plugin, tmp_path):
        """Old lodash in package.json is flagged."""
        (tmp_path / "package.json").write_text(
            '{\n'
            '  "dependencies": {\n'
            '    "lodash": "4.16.0",\n'
            '    "axios": "1.6.0"\n'
            '  }\n'
            '}\n'
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        assert any(r.rule_id == "dep_known_vulnerability" for r in results)

    @pytest.mark.asyncio
    async def test_no_path_returns_empty(self, plugin):
        """Target with no path returns empty."""
        target = Target(url="https://example.com")
        results = await plugin.run(target)
        assert results == []
