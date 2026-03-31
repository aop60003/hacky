# tests/plugins/whitebox/test_js_express_check.py
"""Tests for JsExpressCheckPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.js_express_check import JsExpressCheckPlugin
from vibee_hacker.core.models import Target, Severity


class TestJsExpressCheck:
    @pytest.fixture
    def plugin(self):
        return JsExpressCheckPlugin()

    @pytest.mark.asyncio
    async def test_session_secure_false_detected(self, plugin, tmp_path):
        """secure: false in session cookie config is flagged as MEDIUM."""
        (tmp_path / "app.js").write_text(
            "const session = require('express-session');\n"
            "app.use(session({\n"
            "  secret: 'keyboard cat',\n"
            "  cookie: { secure: false }\n"
            "}));\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.base_severity == Severity.MEDIUM
        assert r.rule_id.startswith("js_express_")
        assert r.cwe_id == "CWE-16"

    @pytest.mark.asyncio
    async def test_secure_settings_clean(self, plugin, tmp_path):
        """Secure Express settings return empty."""
        (tmp_path / "app.js").write_text(
            "const session = require('express-session');\n"
            "app.use(session({\n"
            "  secret: process.env.SESSION_SECRET,\n"
            "  cookie: { secure: true, httpOnly: true }\n"
            "}));\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_path_returns_empty(self, plugin):
        target = Target(url="https://example.com")
        results = await plugin.run(target)
        assert results == []
