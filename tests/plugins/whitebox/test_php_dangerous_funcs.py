# tests/plugins/whitebox/test_php_dangerous_funcs.py
"""Tests for PhpDangerousFuncsPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.php_dangerous_funcs import PhpDangerousFuncsPlugin
from vibee_hacker.core.models import Target, Severity


class TestPhpDangerousFuncs:
    @pytest.fixture
    def plugin(self):
        return PhpDangerousFuncsPlugin()

    @pytest.mark.asyncio
    async def test_eval_detected(self, plugin, tmp_path):
        """eval() in PHP is flagged as CRITICAL."""
        (tmp_path / "app.php").write_text(
            "<?php\n"
            "$code = $_GET['code'];\n"
            "eval($code);\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.base_severity == Severity.CRITICAL
        assert r.rule_id == "php_dangerous_func"
        assert r.cwe_id == "CWE-78"

    @pytest.mark.asyncio
    async def test_clean_php_returns_empty(self, plugin, tmp_path):
        """Clean PHP with no dangerous functions returns empty."""
        (tmp_path / "app.php").write_text(
            "<?php\n"
            "$name = htmlspecialchars($_GET['name']);\n"
            "echo 'Hello, ' . $name;\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_path_returns_empty(self, plugin):
        target = Target(url="https://example.com")
        results = await plugin.run(target)
        assert results == []
