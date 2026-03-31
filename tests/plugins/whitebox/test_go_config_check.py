# tests/plugins/whitebox/test_go_config_check.py
"""Tests for GoConfigCheckPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.go_config_check import GoConfigCheckPlugin
from vibee_hacker.core.models import Target, Severity


class TestGoConfigCheck:
    @pytest.fixture
    def plugin(self):
        return GoConfigCheckPlugin()

    @pytest.mark.asyncio
    async def test_math_rand_detected(self, plugin, tmp_path):
        """math/rand import is flagged as insecure config."""
        (tmp_path / "main.go").write_text(
            "package main\n"
            "import (\n"
            "    \"math/rand\"\n"
            "    \"fmt\"\n"
            ")\n"
            "func main() {\n"
            "    fmt.Println(rand.Intn(100))\n"
            "}\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.base_severity == Severity.HIGH
        assert r.rule_id == "go_insecure_config"
        assert r.cwe_id == "CWE-330"

    @pytest.mark.asyncio
    async def test_crypto_rand_clean(self, plugin, tmp_path):
        """crypto/rand usage returns empty."""
        (tmp_path / "main.go").write_text(
            "package main\n"
            "import (\n"
            "    \"crypto/rand\"\n"
            "    \"fmt\"\n"
            ")\n"
            "func main() {\n"
            "    b := make([]byte, 16)\n"
            "    rand.Read(b)\n"
            "    fmt.Println(b)\n"
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
