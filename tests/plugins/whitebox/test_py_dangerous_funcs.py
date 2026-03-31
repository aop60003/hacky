# tests/plugins/whitebox/test_py_dangerous_funcs.py
"""Tests for PyDangerousFuncsPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.py_dangerous_funcs import PyDangerousFuncsPlugin
from vibee_hacker.core.models import Target, Severity


class TestPyDangerousFuncs:
    @pytest.fixture
    def plugin(self):
        return PyDangerousFuncsPlugin()

    @pytest.mark.asyncio
    async def test_eval_detected(self, plugin, tmp_path):
        """eval() usage is flagged as CRITICAL."""
        (tmp_path / "app.py").write_text(
            "user_input = input('Enter expr: ')\n"
            "result = eval(user_input)\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.base_severity == Severity.CRITICAL
        assert r.rule_id == "py_dangerous_func"
        assert r.cwe_id in ("CWE-78", "CWE-94")

    @pytest.mark.asyncio
    async def test_no_dangerous_funcs(self, plugin, tmp_path):
        """Clean code with no dangerous functions returns empty."""
        (tmp_path / "app.py").write_text(
            "import math\n"
            "result = math.sqrt(16)\n"
            "print(result)\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_path_returns_empty(self, plugin):
        target = Target(url="https://example.com")
        results = await plugin.run(target)
        assert results == []
