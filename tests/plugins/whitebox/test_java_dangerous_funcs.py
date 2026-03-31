# tests/plugins/whitebox/test_java_dangerous_funcs.py
"""Tests for JavaDangerousFuncsPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.java_dangerous_funcs import JavaDangerousFuncsPlugin
from vibee_hacker.core.models import Target, Severity


class TestJavaDangerousFuncs:
    @pytest.fixture
    def plugin(self):
        return JavaDangerousFuncsPlugin()

    @pytest.mark.asyncio
    async def test_runtime_exec_detected(self, plugin, tmp_path):
        """Runtime.exec() in Java is flagged as CRITICAL."""
        (tmp_path / "App.java").write_text(
            "import java.lang.Runtime;\n"
            "public class App {\n"
            "    public void run(String cmd) throws Exception {\n"
            "        Runtime.getRuntime().exec(cmd);\n"
            "    }\n"
            "}\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.base_severity == Severity.CRITICAL
        assert r.rule_id == "java_dangerous_func"
        assert r.cwe_id == "CWE-78"

    @pytest.mark.asyncio
    async def test_clean_java_returns_empty(self, plugin, tmp_path):
        """Clean Java code returns empty."""
        (tmp_path / "App.java").write_text(
            "public class App {\n"
            "    public int add(int a, int b) {\n"
            "        return a + b;\n"
            "    }\n"
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
