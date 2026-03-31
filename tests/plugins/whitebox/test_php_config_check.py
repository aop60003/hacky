# tests/plugins/whitebox/test_php_config_check.py
"""Tests for PhpConfigCheckPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.php_config_check import PhpConfigCheckPlugin
from vibee_hacker.core.models import Target, Severity


class TestPhpConfigCheck:
    @pytest.fixture
    def plugin(self):
        return PhpConfigCheckPlugin()

    @pytest.mark.asyncio
    async def test_display_errors_on_detected(self, plugin, tmp_path):
        """display_errors = On in php.ini or PHP code is flagged."""
        (tmp_path / "php.ini").write_text(
            "[PHP]\n"
            "display_errors = On\n"
            "error_reporting = E_ALL\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.base_severity == Severity.HIGH
        assert r.rule_id == "php_insecure_config"
        assert r.cwe_id == "CWE-16"

    @pytest.mark.asyncio
    async def test_display_errors_off_clean(self, plugin, tmp_path):
        """display_errors = Off is safe and returns empty."""
        (tmp_path / "php.ini").write_text(
            "[PHP]\n"
            "display_errors = Off\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_path_returns_empty(self, plugin):
        target = Target(url="https://example.com")
        results = await plugin.run(target)
        assert results == []
