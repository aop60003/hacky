# tests/plugins/whitebox/test_js_dangerous_funcs.py
"""Tests for JsDangerousFuncsPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.js_dangerous_funcs import JsDangerousFuncsPlugin
from vibee_hacker.core.models import Target, Severity


class TestJsDangerousFuncs:
    @pytest.fixture
    def plugin(self):
        return JsDangerousFuncsPlugin()

    @pytest.mark.asyncio
    async def test_eval_detected(self, plugin, tmp_path):
        """eval() in JS is flagged as CRITICAL."""
        (tmp_path / "app.js").write_text(
            "const userCode = req.body.code;\n"
            "const result = eval(userCode);\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.base_severity == Severity.CRITICAL
        assert r.rule_id == "js_dangerous_func"
        assert r.cwe_id == "CWE-94"

    @pytest.mark.asyncio
    async def test_clean_code(self, plugin, tmp_path):
        """Clean JS code returns empty."""
        (tmp_path / "app.js").write_text(
            "const x = 42;\n"
            "console.log('Hello', x);\n"
            "document.getElementById('out').textContent = x;\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_path_returns_empty(self, plugin):
        target = Target(url="https://example.com")
        results = await plugin.run(target)
        assert results == []
