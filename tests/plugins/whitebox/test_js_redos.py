# tests/plugins/whitebox/test_js_redos.py
"""Tests for JsRedosPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.js_redos import JsRedosPlugin
from vibee_hacker.core.models import Target, Severity


class TestJsRedos:
    @pytest.fixture
    def plugin(self):
        return JsRedosPlugin()

    @pytest.mark.asyncio
    async def test_new_regexp_user_input_detected(self, plugin, tmp_path):
        """new RegExp(req.query.pattern) is flagged as HIGH."""
        (tmp_path / "app.js").write_text(
            "app.get('/search', (req, res) => {\n"
            "  const pattern = req.query.pattern;\n"
            "  const regex = new RegExp(pattern);\n"
            "  const results = data.filter(item => regex.test(item));\n"
            "  res.json(results);\n"
            "});\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.base_severity == Severity.HIGH
        assert r.rule_id == "js_redos"
        assert r.cwe_id == "CWE-1333"

    @pytest.mark.asyncio
    async def test_static_regex_clean(self, plugin, tmp_path):
        """Static regex literal returns empty."""
        (tmp_path / "app.js").write_text(
            "const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$/;\n"
            "function validateEmail(email) { return emailRegex.test(email); }\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_path_returns_empty(self, plugin):
        target = Target(url="https://example.com")
        results = await plugin.run(target)
        assert results == []
