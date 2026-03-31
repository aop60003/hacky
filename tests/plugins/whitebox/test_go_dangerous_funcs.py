# tests/plugins/whitebox/test_go_dangerous_funcs.py
"""Tests for GoDangerousFuncsPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.go_dangerous_funcs import GoDangerousFuncsPlugin
from vibee_hacker.core.models import Target, Severity


class TestGoDangerousFuncs:
    @pytest.fixture
    def plugin(self):
        return GoDangerousFuncsPlugin()

    @pytest.mark.asyncio
    async def test_exec_command_detected(self, plugin, tmp_path):
        """exec.Command() with a variable is flagged as CRITICAL."""
        (tmp_path / "main.go").write_text(
            "package main\n"
            "import \"os/exec\"\n"
            "func run(cmd string) {\n"
            "    exec.Command(cmd).Run()\n"
            "}\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.base_severity == Severity.CRITICAL
        assert r.rule_id == "go_dangerous_func"
        assert r.cwe_id == "CWE-78"

    @pytest.mark.asyncio
    async def test_clean_go_returns_empty(self, plugin, tmp_path):
        """Clean Go code returns empty."""
        (tmp_path / "main.go").write_text(
            "package main\n"
            "import \"fmt\"\n"
            "func main() {\n"
            "    fmt.Println(\"Hello, world!\")\n"
            "}\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_path_returns_empty(self, plugin):
        target = Target(url="https://example.com")
        results = await plugin.run(target)
        assert results == []
